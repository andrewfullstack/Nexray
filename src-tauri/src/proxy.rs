//! System-proxy supervisor.
//!
//! Tells the OS to route proxy-aware apps' SOCKS traffic through Nexray's
//! local SOCKS listener. From the user's perspective this feels like a VPN
//! for everything that honours system proxy settings (Safari, Chrome, curl
//! `--proxy`, most native apps).
//!
//! What this is NOT:
//! - It does NOT capture every packet (that's TUN mode or, on macOS, an
//!   NEPacketTunnelProvider Network Extension). Apps that ignore system
//!   proxy settings (some games, BitTorrent clients) still bypass us.
//! - It does NOT show up in System Settings → VPN. That's a Network
//!   Extension entitlement; see `docs/MACOS_VPN.md`.
//!
//! Per-OS backend:
//! - **macOS**: `networksetup -setsocksfirewallproxy …` against the network
//!   service whose interface owns the default route. May prompt for the
//!   admin password on Ventura+; we let macOS handle the prompt.
//! - **Windows**: HKCU registry under
//!   `Software\Microsoft\Windows\CurrentVersion\Internet Settings` —
//!   `ProxyEnable=1`, `ProxyServer=socks=host:port`, then
//!   `InternetSetOptionW(SETTINGS_CHANGED|REFRESH)` to push the change to
//!   already-running WinINet clients (Edge, IE, most apps that honor
//!   system proxy). No admin required; per-user only.
//! - **Linux (GNOME)**: `gsettings set org.gnome.system.proxy mode manual`
//!   plus `…socks host/port`. KDE / sway / non-GNOME desktops are not
//!   supported in this build — we surface a clear error instead of silently
//!   succeeding.

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;
use std::sync::Mutex;

use nexray_core::SystemProxyStatus;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("system proxy is not supported on this platform")]
    UnsupportedPlatform,
    #[error("`{cmd}` exited {status}: {stderr}")]
    Command {
        cmd: &'static str,
        status: i32,
        stderr: String,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no active network service detected")]
    NoActiveService,
    /// Catch-all for platform-specific failures that don't fit `Command`
    /// (e.g. Windows registry errors, missing GNOME schema on Linux).
    #[error("{0}")]
    Platform(String),
}

/// Re-exported public state type — same shape as the generated
/// `SystemProxyStatus` IPC schema so commands can pass it through unchanged.
pub type ProxyState = SystemProxyStatus;

fn empty_state() -> ProxyState {
    ProxyState {
        enabled: false,
        host: None,
        port: None,
        service: None,
    }
}

pub struct ProxySupervisor {
    state: Mutex<ProxyState>,
}

impl Default for ProxySupervisor {
    fn default() -> Self {
        Self {
            state: Mutex::new(empty_state()),
        }
    }
}

impl ProxySupervisor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn status(&self) -> ProxyState {
        self.state
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| empty_state())
    }

    /// Turn on the system SOCKS proxy pointing at `host:port`. Returns the
    /// updated state on success.
    pub fn enable(&self, host: &str, port: u16) -> Result<ProxyState, ProxyError> {
        #[cfg(target_os = "macos")]
        let result = self.enable_macos(host, port);
        #[cfg(target_os = "windows")]
        let result = self.enable_windows(host, port);
        #[cfg(target_os = "linux")]
        let result = self.enable_linux(host, port);
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        let result: Result<ProxyState, ProxyError> = {
            let _ = (host, port);
            Err(ProxyError::UnsupportedPlatform)
        };
        result
    }

    pub fn disable(&self) -> Result<ProxyState, ProxyError> {
        #[cfg(target_os = "macos")]
        let result = self.disable_macos();
        #[cfg(target_os = "windows")]
        let result = self.disable_windows();
        #[cfg(target_os = "linux")]
        let result = self.disable_linux();
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        let result: Result<ProxyState, ProxyError> = Err(ProxyError::UnsupportedPlatform);
        result
    }

    #[cfg(target_os = "macos")]
    fn enable_macos(&self, host: &str, port: u16) -> Result<ProxyState, ProxyError> {
        let service = active_network_service()?;
        run_networksetup(&["-setsocksfirewallproxy", &service, host, &port.to_string()])?;
        run_networksetup(&["-setsocksfirewallproxystate", &service, "on"])?;

        let new_state = ProxyState {
            enabled: true,
            host: Some(host.to_string()),
            port: Some(port),
            service: Some(service),
        };
        if let Ok(mut guard) = self.state.lock() {
            *guard = new_state.clone();
        }
        Ok(new_state)
    }

    #[cfg(target_os = "macos")]
    fn disable_macos(&self) -> Result<ProxyState, ProxyError> {
        let service = self
            .state
            .lock()
            .ok()
            .and_then(|s| s.service.clone())
            .or_else(|| active_network_service().ok())
            .ok_or(ProxyError::NoActiveService)?;
        run_networksetup(&["-setsocksfirewallproxystate", &service, "off"])?;
        let new_state = empty_state();
        if let Ok(mut guard) = self.state.lock() {
            *guard = new_state.clone();
        }
        Ok(new_state)
    }

    #[cfg(target_os = "windows")]
    fn enable_windows(&self, host: &str, port: u16) -> Result<ProxyState, ProxyError> {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(WININET_KEY)
            .map_err(|e| ProxyError::Platform(format!("open HKCU\\{WININET_KEY}: {e}")))?;

        let value = wininet_proxy_value(host, port);
        key.set_value("ProxyServer", &value)
            .map_err(|e| ProxyError::Platform(format!("set ProxyServer: {e}")))?;
        key.set_value("ProxyEnable", &1u32)
            .map_err(|e| ProxyError::Platform(format!("set ProxyEnable: {e}")))?;
        // Always bypass the proxy for localhost / intranet so we don't
        // accidentally route ourselves through ourselves.
        let _ = key.set_value("ProxyOverride", &"<local>");

        refresh_wininet();

        let new_state = ProxyState {
            enabled: true,
            host: Some(host.to_string()),
            port: Some(port),
            service: Some("WinINET (current user)".to_string()),
        };
        if let Ok(mut guard) = self.state.lock() {
            *guard = new_state.clone();
        }
        Ok(new_state)
    }

    #[cfg(target_os = "windows")]
    fn disable_windows(&self) -> Result<ProxyState, ProxyError> {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        // Best-effort: flip ProxyEnable off and leave the host/port value in
        // place so the user can re-enable from System Settings later if they
        // want. If the key is missing entirely there's nothing to disable —
        // treat as success and just refresh.
        if let Ok(key) = hkcu.open_subkey_with_flags(WININET_KEY, KEY_SET_VALUE) {
            key.set_value("ProxyEnable", &0u32)
                .map_err(|e| ProxyError::Platform(format!("clear ProxyEnable: {e}")))?;
        }
        refresh_wininet();

        let new_state = empty_state();
        if let Ok(mut guard) = self.state.lock() {
            *guard = new_state.clone();
        }
        Ok(new_state)
    }

    #[cfg(target_os = "linux")]
    fn enable_linux(&self, host: &str, port: u16) -> Result<ProxyState, ProxyError> {
        require_gnome_proxy_schema()?;
        run_gsettings(&["set", "org.gnome.system.proxy", "mode", "manual"])?;
        run_gsettings(&["set", "org.gnome.system.proxy.socks", "host", host])?;
        run_gsettings(&[
            "set",
            "org.gnome.system.proxy.socks",
            "port",
            &port.to_string(),
        ])?;

        let new_state = ProxyState {
            enabled: true,
            host: Some(host.to_string()),
            port: Some(port),
            service: Some("GNOME (org.gnome.system.proxy)".to_string()),
        };
        if let Ok(mut guard) = self.state.lock() {
            *guard = new_state.clone();
        }
        Ok(new_state)
    }

    #[cfg(target_os = "linux")]
    fn disable_linux(&self) -> Result<ProxyState, ProxyError> {
        require_gnome_proxy_schema()?;
        run_gsettings(&["set", "org.gnome.system.proxy", "mode", "none"])?;

        let new_state = empty_state();
        if let Ok(mut guard) = self.state.lock() {
            *guard = new_state.clone();
        }
        Ok(new_state)
    }
}

impl Drop for ProxySupervisor {
    fn drop(&mut self) {
        // Best-effort: if we enabled the proxy at runtime, turn it back off
        // when the app exits so we don't leave the system in a broken state.
        let was_enabled = self.state.lock().map(|s| s.enabled).unwrap_or(false);
        if was_enabled {
            let _ = self.disable();
        }
    }
}

#[cfg(target_os = "macos")]
fn run_networksetup(args: &[&str]) -> Result<String, ProxyError> {
    let output = Command::new("/usr/sbin/networksetup").args(args).output()?;
    if !output.status.success() {
        return Err(ProxyError::Command {
            cmd: "networksetup",
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// ---------------------------------------------------------------------------
// Windows backend helpers.
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
const WININET_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Format the `ProxyServer` registry value WinINet expects for a SOCKS-only
/// proxy: `socks=host:port`. Per-protocol prefixes (`http=`, `https=`,
/// `socks=`) are honored by Edge, IE, Chromium, and most native apps that
/// read the system proxy. Bare `host:port` would imply HTTP-only.
pub fn wininet_proxy_value(host: &str, port: u16) -> String {
    format!("socks={host}:{port}")
}

/// Push the registry change to running WinINet clients. Without this they
/// keep using the previously-cached proxy until the next process restart.
#[cfg(target_os = "windows")]
fn refresh_wininet() {
    use std::ptr;
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    // Best-effort: ignore return value. Some systems block the refresh
    // (e.g. group policy lockdown), and there's nothing useful we can do
    // about it from here.
    unsafe {
        InternetSetOptionW(
            ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            ptr::null(),
            0,
        );
        InternetSetOptionW(ptr::null_mut(), INTERNET_OPTION_REFRESH, ptr::null(), 0);
    }
}

// ---------------------------------------------------------------------------
// Linux backend helpers.
// ---------------------------------------------------------------------------

/// Run `gsettings <args>`, returning stdout on success.
#[cfg(target_os = "linux")]
fn run_gsettings(args: &[&str]) -> Result<String, ProxyError> {
    let output = Command::new("gsettings").args(args).output().map_err(|e| {
        ProxyError::Platform(format!(
            "`gsettings` not available ({e}); only GNOME-based desktops are supported on Linux currently"
        ))
    })?;
    if !output.status.success() {
        return Err(ProxyError::Command {
            cmd: "gsettings",
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Verify the GNOME proxy schema is reachable before we touch it. Saves us
/// from leaving the system in a half-applied state on KDE / sway / minimal
/// installs that have `gsettings` but not the schema.
#[cfg(target_os = "linux")]
fn require_gnome_proxy_schema() -> Result<(), ProxyError> {
    let output = Command::new("gsettings")
        .args(["get", "org.gnome.system.proxy", "mode"])
        .output()
        .map_err(|e| {
            ProxyError::Platform(format!(
                "`gsettings` not available ({e}); only GNOME-based desktops are supported on Linux currently"
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ProxyError::Platform(format!(
            "`org.gnome.system.proxy` schema not available — only GNOME-based desktops are supported on Linux currently. {}",
            stderr.trim()
        )));
    }
    Ok(())
}

/// Resolve the network service that's actually carrying internet traffic
/// right now. Tries, in order:
///   1. The default route's interface — the single source of truth for
///      "which interface is online by default". Map it to its
///      `networksetup` Hardware Port via `-listallhardwareports`.
///   2. The first enabled entry in `-listnetworkserviceorder` — fallback
///      for offline / no-default-route states.
///   3. `"Wi-Fi"` — last-ditch default; most macOS users have it.
///
/// This is what fixes the "proxy went on USB Ethernet but I'm using Wi-Fi"
/// case: the priority-order list ranks USB Ethernet above Wi-Fi by default,
/// but the actual default route is via en0/Wi-Fi.
#[cfg(target_os = "macos")]
fn active_network_service() -> Result<String, ProxyError> {
    if let Some(iface) = default_route_interface() {
        let hwports = run_networksetup(&["-listallhardwareports"])?;
        if let Some(name) = service_for_interface(&hwports, &iface) {
            return Ok(name);
        }
    }
    let listing = run_networksetup(&["-listnetworkserviceorder"])?;
    if let Some(name) = parse_first_service(&listing) {
        return Ok(name);
    }
    Ok("Wi-Fi".to_string())
}

/// `route -n get default` → interface name (e.g. `en0`). Returns `None` if
/// there's no default route or the command output can't be parsed.
#[cfg(target_os = "macos")]
fn default_route_interface() -> Option<String> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_default_interface(&text)
}

/// Parse a `route -n get default` block. Looks for `interface: <name>`.
pub fn parse_default_interface(text: &str) -> Option<String> {
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("interface:") {
            let name = rest.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Parse `networksetup -listallhardwareports` and return the Hardware Port
/// name whose `Device:` matches `iface`. Format:
///
///   Hardware Port: Wi-Fi
///   Device: en0
///   Ethernet Address: ...
///
///   Hardware Port: USB 10/100/1000 LAN
///   Device: en4
///   ...
pub fn service_for_interface(hwports: &str, iface: &str) -> Option<String> {
    let mut pending_port: Option<String> = None;
    for line in hwports.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Hardware Port:") {
            pending_port = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = t.strip_prefix("Device:") {
            if rest.trim() == iface {
                if let Some(port) = pending_port.take() {
                    return Some(port);
                }
            }
        }
    }
    None
}

/// Parse the output of `networksetup -listnetworkserviceorder`. Format:
///
///   An asterisk (*) denotes that a network service is disabled.
///   (1) Wi-Fi
///   (Hardware Port: Wi-Fi, Device: en0)
///
///   (2) iPhone USB
///   (Hardware Port: iPhone USB, Device: en6)
///
/// We pick the first `(N) <name>` line whose `(N)` is NOT preceded by `*`.
pub fn parse_first_service(listing: &str) -> Option<String> {
    for line in listing.lines() {
        let t = line.trim_start();
        // Disabled services are prefixed with `*`.
        if t.starts_with("(*)") || t.starts_with("*") {
            continue;
        }
        if let Some(rest) = t.strip_prefix('(') {
            // Format: "(N) Service Name". Split on the first ')'.
            if let Some((num, name)) = rest.split_once(')') {
                if num.chars().all(|c| c.is_ascii_digit()) {
                    let cleaned = name.trim();
                    if !cleaned.is_empty() && !cleaned.starts_with("Hardware Port:") {
                        return Some(cleaned.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    const SAMPLE_LISTING: &str = "An asterisk (*) denotes that a network service is disabled.\n(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(2) iPhone USB\n(Hardware Port: iPhone USB, Device: en6)\n";

    const DISABLED_FIRST: &str = "An asterisk (*) denotes that a network service is disabled.\n(*) Bluetooth PAN\n(Hardware Port: Bluetooth PAN, Device: en7)\n\n(2) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n";

    // Real `networksetup -listallhardwareports` output from the bug report:
    // a Mac with a USB Ethernet dongle wired up + Wi-Fi as the active uplink.
    const HWPORTS_REAL: &str = "\nHardware Port: USB 10/100/1000 LAN\nDevice: en4\nEthernet Address: 00:e0:4c:68:15:d9\n\nHardware Port: Ethernet Adapter (en5)\nDevice: en5\nEthernet Address: 82:20:c1:d5:55:b1\n\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: bc:d0:74:06:39:21\n\nHardware Port: Thunderbolt 1\nDevice: en1\nEthernet Address: 36:42:26:f2:74:40\n\nVLAN Configurations\n===================\n";

    const ROUTE_DEFAULT: &str = "   route to: default\ndestination: default\n    gateway: 192.168.4.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONED>\n";

    #[test]
    fn parses_first_enabled_service() {
        assert_eq!(parse_first_service(SAMPLE_LISTING), Some("Wi-Fi".into()));
    }

    #[test]
    fn skips_disabled_first_entry() {
        assert_eq!(parse_first_service(DISABLED_FIRST), Some("Wi-Fi".into()));
    }

    #[test]
    fn handles_empty_input() {
        assert_eq!(parse_first_service(""), None);
    }

    #[test]
    fn default_state_is_disabled() {
        let s = empty_state();
        assert!(!s.enabled);
        assert_eq!(s.host, None);
    }

    #[test]
    fn parses_default_route_interface() {
        assert_eq!(parse_default_interface(ROUTE_DEFAULT), Some("en0".into()));
        assert_eq!(parse_default_interface(""), None);
        assert_eq!(parse_default_interface("garbage"), None);
    }

    #[test]
    fn maps_real_default_interface_to_wifi_not_usb_ethernet() {
        // The bug: priority-order picks USB 10/100/1000 LAN, but the actual
        // default-route interface is en0 → Wi-Fi.
        assert_eq!(
            service_for_interface(HWPORTS_REAL, "en0"),
            Some("Wi-Fi".into()),
        );
        // Sanity check the wired one too.
        assert_eq!(
            service_for_interface(HWPORTS_REAL, "en4"),
            Some("USB 10/100/1000 LAN".into()),
        );
    }

    #[test]
    fn returns_none_for_unmapped_interface() {
        assert_eq!(service_for_interface(HWPORTS_REAL, "tun42"), None);
        assert_eq!(service_for_interface("", "en0"), None);
    }

    #[test]
    fn windows_proxy_value_formats_as_socks() {
        // WinINet honours the per-protocol prefix; bare "host:port" would
        // mean HTTP-only and break SOCKS-aware clients.
        assert_eq!(
            wininet_proxy_value("127.0.0.1", 10808),
            "socks=127.0.0.1:10808"
        );
        assert_eq!(wininet_proxy_value("::1", 1080), "socks=::1:1080");
    }
}
