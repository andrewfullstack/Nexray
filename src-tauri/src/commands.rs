//! Tauri IPC commands. Every command takes a typed argument and returns a
//! typed response. The argument struct is decoded via `serde` from JSON the
//! UI sends; the Rust type is generated from the Zod schema.

use std::path::PathBuf;
use std::time::SystemTime;

use nexray_core::rules_conf;
use nexray_core::xray_config::{materialize, XrayConfigOptions};
use nexray_core::{
    AddSubscriptionRequest, AppInfo, AppSettings, ConnectRequest, ConnectionState,
    ConnectionStatus, PoolEntry, Profile, RoutingSettings, SetRoutingRequest, SetSettingsRequest,
    Subscription, SubscriptionIdRequest, SystemProxyStatus, TrafficStats, TunCapabilities,
    TunState, TunStatus,
};
use tauri::{AppHandle, Manager, State};

use crate::core::XraySidecar;
use crate::state::AppState;
use crate::stats::StatsClient;
use crate::subscription::{
    self as sub_mod, build_pool, fetch_and_classify, pending, probe_all, validate_add, ProbeRecord,
};
use crate::tun::TunSupervisor;

/// Smoke-test ping. Useful for verifying IPC is wired before any real
/// connect/disconnect cycle.
#[tauri::command]
pub fn ping() -> &'static str {
    "pong"
}

#[tauri::command]
pub async fn connect(
    req: ConnectRequest,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<ConnectionStatus, String> {
    let socks_port = req.socks_port.unwrap_or(10808);
    let stats_port = pick_loopback_port();
    let routing = state.routing.lock().map_err(|e| e.to_string())?.clone();
    let extra_rules = match rules_file_read_translated(&app) {
        Ok(rules) => rules,
        Err(e) => {
            tracing::warn!(target: "connect", "rules.conf load failed: {e}");
            vec![]
        }
    };

    // Detect the local interface's IP so xray's `direct` outbound can be
    // pinned to it via `sendThrough`. Without this, when TUN later captures
    // the default route, xray's direct outbound socket would route into
    // the tunnel and loop forever ("creating too many tcp ports" cascade).
    // Setting sendThrough is harmless when TUN is off.
    let local_ip = detect_local_ip();

    let config = materialize(
        &req.profile,
        &XrayConfigOptions {
            socks_port,
            stats_port: Some(stats_port),
            log_level: "warning",
            routing,
            extra_rules,
            direct_send_through: local_ip.clone(),
        },
    )
    .map_err(|e| e.to_string())?;
    let config_json = serde_json::to_string(&config).map_err(|e| e.to_string())?;

    let sidecar = ensure_sidecar(&state, &app)?;
    let profile_id = profile_id(&req.profile).to_string();

    sidecar
        .start(profile_id, socks_port, config_json)
        .map_err(|e| e.to_string())?;
    *state.active_profile.lock().map_err(|e| e.to_string())? = Some(req.profile);
    Ok(sidecar.status())
}

#[tauri::command]
pub async fn disconnect(state: State<'_, AppState>) -> Result<ConnectionStatus, String> {
    let guard = state.sidecar.lock().map_err(|e| e.to_string())?;
    if let Some(sidecar) = guard.as_ref() {
        sidecar.stop().map_err(|e| e.to_string())?;
        *state.active_profile.lock().map_err(|e| e.to_string())? = None;
        return Ok(sidecar.status());
    }
    Ok(disconnected())
}

#[tauri::command]
pub async fn status(state: State<'_, AppState>) -> Result<ConnectionStatus, String> {
    let guard = state.sidecar.lock().map_err(|e| e.to_string())?;
    if let Some(sidecar) = guard.as_ref() {
        return Ok(sidecar.status());
    }
    Ok(disconnected())
}

#[tauri::command]
pub async fn traffic_stats(state: State<'_, AppState>) -> Result<TrafficStats, String> {
    let guard = state.sidecar.lock().map_err(|e| e.to_string())?;
    let Some(sidecar) = guard.as_ref() else {
        return Ok(StatsClient::unavailable());
    };
    let s = sidecar.status();
    if !matches!(
        s.state,
        ConnectionState::Connected | ConnectionState::Connecting
    ) {
        return Ok(StatsClient::unavailable());
    }
    // Stats API binding port is currently not surfaced through ConnectionStatus
    // (it's an internal detail). Phase 2 ships a stub; Phase 2.5 will plumb
    // the port through and run the real `xray api statsquery` shell-out.
    Ok(StatsClient::unavailable())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ensure_sidecar(state: &State<'_, AppState>, app: &AppHandle) -> Result<XraySidecar, String> {
    let mut guard = state.sidecar.lock().map_err(|e| e.to_string())?;
    if let Some(existing) = guard.as_ref() {
        return Ok(existing.clone());
    }
    let path = resolve_xray_path(app)?;
    if !path.exists() {
        return Err(format_missing_xray_error(app));
    }
    let sidecar = XraySidecar::new(path, vec!["-config".into(), "stdin:".into()]);
    if let Ok(p) = crate::runtime::pid_file_path(app, "xray.pid") {
        sidecar.set_pid_file(p);
    }
    *guard = Some(sidecar.clone());
    Ok(sidecar)
}

/// Multi-line, actionable error for the "xray-core binary missing" case.
/// Lists every path the resolver checked and the three install options the
/// user can take to make Connect work.
fn format_missing_xray_error(app: &AppHandle) -> String {
    let bin = if cfg!(windows) { "xray.exe" } else { "xray" };
    let resource_path = app
        .path()
        .resource_dir()
        .ok()
        .map(|d| d.join("binaries").join(bin));
    let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join(bin);

    let mut msg = String::from("xray-core binary not found. Searched (first match wins):\n");
    msg.push_str("  · $NEXRAY_XRAY_BIN — not set or path doesn't exist\n");
    if let Some(p) = resource_path {
        msg.push_str(&format!("  · {} (bundled) — missing\n", p.display()));
    }
    msg.push_str(&format!("  · {} (dev) — missing\n", dev_path.display()));
    msg.push_str("  · $PATH (Homebrew, system install) — not found\n");
    msg.push_str("\nFix any one:\n");
    msg.push_str("  1. brew install xray\n");
    msg.push_str("  2. export NEXRAY_XRAY_BIN=/path/to/xray   (then restart the app)\n");
    msg.push_str(&format!("  3. cp /path/to/xray {}", dev_path.display()));
    msg
}

/// Resolve the xray-core binary path. Tries, in order:
///   1. `NEXRAY_XRAY_BIN` env var (dev / CI / power users)
///   2. Tauri's bundled resource dir (`<resources>/binaries/xray`)
///   3. Dev workspace path (`<src-tauri>/binaries/xray`)
///   4. First `xray` on `PATH` (Homebrew, `apt install`, etc.)
///
/// Falls through to the bundled path so the error message points users at
/// the canonical install location.
fn resolve_xray_path(app: &AppHandle) -> Result<PathBuf, String> {
    let bin = if cfg!(windows) { "xray.exe" } else { "xray" };

    if let Ok(p) = std::env::var("NEXRAY_XRAY_BIN") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Ok(path);
        }
    }

    let resource_dir = app.path().resource_dir().map_err(|e| e.to_string())?;
    let resource_root = resource_dir.join("binaries");
    let bundled = resource_root.join(bin);
    if bundled.exists() {
        return Ok(bundled);
    }
    if let Some(p) = find_in_subdirs(&resource_root, bin) {
        return Ok(p);
    }

    let dev_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("binaries");
    let dev = dev_root.join(bin);
    if dev.exists() {
        return Ok(dev);
    }
    if let Some(p) = find_in_subdirs(&dev_root, bin) {
        return Ok(p);
    }

    if let Some(p) = find_on_path(bin) {
        return Ok(p);
    }

    Ok(bundled)
}

/// One-level-deep scan: look for `<root>/<any-subdir>/<bin>`. Used to find
/// xray-core / tun2socks when the user drops the unzipped release archive
/// directly under `binaries/` (e.g. `binaries/Xray-macos-arm64-v8a/xray`).
fn find_in_subdirs(root: &std::path::Path, bin: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let candidate = path.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Cross-platform "first match on `PATH`". Returns `None` if not found.
fn find_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn profile_id(p: &Profile) -> &str {
    match p {
        Profile::CdnWs(p) => &p.id,
        Profile::Reality(p) => &p.id,
    }
}

/// Pick a free loopback port for the Stats API. Per DEVELOPMENT.md §12 rule 6
/// the listener is always 127.0.0.1; we draw a random ephemeral port so two
/// concurrent shell instances don't collide.
fn pick_loopback_port() -> u16 {
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .ok()
        .and_then(|l| l.local_addr().ok());
    match listener {
        Some(std::net::SocketAddr::V4(a)) => a.port(),
        _ => 58080,
    }
}

fn disconnected() -> ConnectionStatus {
    ConnectionStatus {
        state: ConnectionState::Disconnected,
        profile_id: None,
        socks_port: None,
        since_ms: None,
        last_error: None,
    }
}

// ---------------------------------------------------------------------------
// Phase 4 — subscriptions / pool
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn subscriptions_list(state: State<'_, AppState>) -> Result<Vec<Subscription>, String> {
    let guard = state.subscriptions.lock().map_err(|e| e.to_string())?;
    let mut out: Vec<Subscription> = guard.values().cloned().collect();
    out.sort_by_key(|s| s.added_ms);
    Ok(out)
}

#[tauri::command]
pub async fn subscription_add(
    req: AddSubscriptionRequest,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<Subscription, String> {
    validate_add(&req).map_err(|e| e.to_string())?;
    let id = sub_mod::subscription_id(&req.url);
    {
        let guard = state.subscriptions.lock().map_err(|e| e.to_string())?;
        if guard.contains_key(&id) {
            return Err("subscription URL already added".into());
        }
    }

    // Insert pending then asynchronously fetch+classify.
    let mut sub = pending(&req.url, req.name.as_deref());
    {
        let mut guard = state.subscriptions.lock().map_err(|e| e.to_string())?;
        guard.insert(sub.id.clone(), sub.clone());
    }
    persist(&app, &state)?;

    let result = fetch_and_classify(&sub.id, &sub.url, &sub.name, sub.added_ms).await;
    match result {
        Ok(updated) => {
            sub = updated;
        }
        Err(e) => {
            sub.last_fetch_error = Some(e.to_string());
        }
    }
    {
        let mut guard = state.subscriptions.lock().map_err(|e| e.to_string())?;
        guard.insert(sub.id.clone(), sub.clone());
    }
    persist(&app, &state)?;
    Ok(sub)
}

#[tauri::command]
pub async fn subscription_delete(
    req: SubscriptionIdRequest,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    {
        let mut guard = state.subscriptions.lock().map_err(|e| e.to_string())?;
        guard.remove(&req.id);
    }
    persist(&app, &state)?;
    Ok(())
}

#[tauri::command]
pub async fn subscription_refresh(
    req: SubscriptionIdRequest,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<Subscription, String> {
    let (url, name, added_ms) = {
        let guard = state.subscriptions.lock().map_err(|e| e.to_string())?;
        let s = guard
            .get(&req.id)
            .ok_or_else(|| "no such subscription".to_string())?;
        (s.url.clone(), s.name.clone(), s.added_ms)
    };

    let result = fetch_and_classify(&req.id, &url, &name, added_ms).await;
    let mut guard = state.subscriptions.lock().map_err(|e| e.to_string())?;
    let existing = guard
        .get(&req.id)
        .cloned()
        .ok_or_else(|| "subscription deleted mid-refresh".to_string())?;
    let updated = match result {
        Ok(s) => s,
        Err(e) => Subscription {
            // Preserve last-known profiles per DEVELOPMENT.md §5.4 — failed
            // refresh keeps serving the cached pool.
            last_fetch_error: Some(e.to_string()),
            ..existing
        },
    };
    guard.insert(updated.id.clone(), updated.clone());
    drop(guard);
    persist(&app, &state)?;
    Ok(updated)
}

#[tauri::command]
pub async fn pool_list(state: State<'_, AppState>) -> Result<Vec<PoolEntry>, String> {
    let subs = state
        .subscriptions
        .lock()
        .map_err(|e| e.to_string())?
        .clone();
    let probes = state.probes.lock().map_err(|e| e.to_string())?;
    let mut probes_map = std::collections::HashMap::new();
    for (k, v) in probes.iter() {
        probes_map.insert(
            k.clone(),
            ProbeRecord {
                latency_ms: v.latency_ms,
                last_probe_ms: v.last_probe_ms,
            },
        );
    }
    drop(probes);
    Ok(build_pool(&subs, &probes_map))
}

#[tauri::command]
pub async fn pool_probe_all(state: State<'_, AppState>) -> Result<Vec<PoolEntry>, String> {
    // Snapshot profiles to probe (drop the lock before await).
    let profiles: Vec<Profile> = {
        let guard = state.subscriptions.lock().map_err(|e| e.to_string())?;
        guard
            .values()
            .flat_map(|s| s.profiles.iter().cloned())
            .collect()
    };
    let results = probe_all(&profiles).await;
    let now_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    {
        let mut probes = state.probes.lock().map_err(|e| e.to_string())?;
        for (id, latency) in results {
            probes.insert(
                id,
                ProbeRecord {
                    latency_ms: latency,
                    last_probe_ms: Some(now_ms),
                },
            );
        }
    }
    pool_list(state).await
}

// ---------------------------------------------------------------------------
// Phase 7.5 — system proxy (macOS networksetup, Windows + Linux deferred)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn system_proxy_status(state: State<'_, AppState>) -> Result<SystemProxyStatus, String> {
    Ok(state.system_proxy.status())
}

#[tauri::command]
pub async fn system_proxy_enable(state: State<'_, AppState>) -> Result<SystemProxyStatus, String> {
    // Read the current SOCKS port from the active sidecar so the OS routes
    // through the right listener. Refuses if no profile is connected.
    let conn = {
        let guard = state.sidecar.lock().map_err(|e| e.to_string())?;
        guard.as_ref().map(|s| s.status())
    };
    let Some(conn) = conn else {
        return Err("connect to a profile before enabling the system proxy".into());
    };
    if !matches!(
        conn.state,
        ConnectionState::Connected | ConnectionState::Connecting
    ) {
        return Err("xray sidecar is not connected".into());
    }
    let Some(socks_port) = conn.socks_port else {
        return Err("SOCKS inbound port not yet known".into());
    };
    state
        .system_proxy
        .enable("127.0.0.1", socks_port)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn system_proxy_disable(state: State<'_, AppState>) -> Result<SystemProxyStatus, String> {
    state.system_proxy.disable().map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Phase 6 — TUN
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn tun_capabilities(app: AppHandle) -> Result<TunCapabilities, String> {
    let path = resolve_tun_binary_path(&app)?;
    let binary_present = path.exists();
    let platform = current_platform();
    let supported = matches!(platform.as_str(), "macos" | "windows" | "linux");
    let reason = if !supported {
        Some(format!("TUN not supported on {platform}"))
    } else if !binary_present {
        Some(format!(
            "tun2socks binary missing from {} — populate scripts/fetch-core.mjs TUN2SOCKS map",
            path.display()
        ))
    } else {
        None
    };
    Ok(TunCapabilities {
        supported: supported && binary_present,
        platform,
        binary_present,
        reason,
    })
}

#[tauri::command]
pub async fn tun_status(state: State<'_, AppState>) -> Result<TunStatus, String> {
    let guard = state.tun.lock().map_err(|e| e.to_string())?;
    if let Some(t) = guard.as_ref() {
        return Ok(t.status());
    }
    Ok(disabled_tun())
}

#[tauri::command]
pub async fn tun_enable(state: State<'_, AppState>, app: AppHandle) -> Result<TunStatus, String> {
    let conn = {
        let guard = state.sidecar.lock().map_err(|e| e.to_string())?;
        guard.as_ref().map(|s| s.status())
    };
    let Some(conn) = conn else {
        return Err("connect to a profile before enabling TUN".into());
    };
    if !matches!(
        conn.state,
        ConnectionState::Connected | ConnectionState::Connecting
    ) {
        return Err("xray sidecar is not connected".into());
    }
    let Some(socks_port) = conn.socks_port else {
        return Err("SOCKS inbound port not yet known".into());
    };

    // Resolve the active profile's address(es) so the launcher can install
    // /32 bypass routes — without those, xray's upstream connection would
    // route into the tunnel and loop.
    let bypass_ips = resolve_active_profile_ips(&state)?;

    let supervisor = ensure_tun(&state, &app)?;
    let socks_addr = format!("127.0.0.1:{socks_port}");
    // Iface name is a HINT — the launcher script may bump to utun9/10/...
    // if utun8 is leaked from a previous session and the kernel hasn't
    // reclaimed it. Pick a high base to dodge system VPN/iCloud Private
    // Relay devices.
    let iface = if cfg!(target_os = "macos") {
        "utun100"
    } else {
        "nexray-tun"
    };
    supervisor
        .enable(&socks_addr, iface, &bypass_ips)
        .map_err(|e| e.to_string())?;
    Ok(supervisor.status())
}

/// Best-effort: figure out the IP the kernel would use to reach a public
/// destination right now. Bind a UDP socket to `0.0.0.0:0`, then connect()
/// it (no packets actually sent) and read the local address the kernel
/// picked. Works on every platform and doesn't need root.
///
/// Important: call this BEFORE TUN is enabled, otherwise the answer is
/// the utun device's IP (which is exactly what we don't want for
/// sendThrough).
fn detect_local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    let ip = addr.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    Some(ip.to_string())
}

/// Resolve the active profile's `address` (IP literal or hostname) to one
/// or more IPv4/IPv6 addresses. Returns an empty Vec if no profile is
/// active or DNS fails — in that case the launcher skips bypass route
/// installation. We don't fail hard on this because TUN bring-up is still
/// useful for diagnosis.
fn resolve_active_profile_ips(state: &State<'_, AppState>) -> Result<Vec<String>, String> {
    use std::net::ToSocketAddrs;
    let address = {
        let guard = state.active_profile.lock().map_err(|e| e.to_string())?;
        guard.as_ref().map(|p| match p {
            Profile::CdnWs(c) => c.address.clone(),
            Profile::Reality(r) => r.address.clone(),
        })
    };
    let Some(address) = address else {
        return Ok(vec![]);
    };
    let target = format!("{address}:443");
    let ips: Vec<String> = target
        .to_socket_addrs()
        .map(|iter| iter.map(|sa| sa.ip().to_string()).collect())
        .unwrap_or_default();
    Ok(ips)
}

#[tauri::command]
pub async fn tun_disable(state: State<'_, AppState>) -> Result<TunStatus, String> {
    let guard = state.tun.lock().map_err(|e| e.to_string())?;
    if let Some(t) = guard.as_ref() {
        t.disable().map_err(|e| e.to_string())?;
        return Ok(t.status());
    }
    Ok(disabled_tun())
}

fn ensure_tun(state: &State<'_, AppState>, app: &AppHandle) -> Result<TunSupervisor, String> {
    let mut guard = state.tun.lock().map_err(|e| e.to_string())?;
    if let Some(existing) = guard.as_ref() {
        return Ok(existing.clone());
    }
    let path = resolve_tun_binary_path(app)?;
    let supervisor = TunSupervisor::new(path);
    if let Ok(p) = crate::runtime::pid_file_path(app, "tun2socks.pid") {
        supervisor.set_pid_file(p);
    }
    *guard = Some(supervisor.clone());
    Ok(supervisor)
}

fn current_platform() -> String {
    if cfg!(target_os = "macos") {
        "macos".into()
    } else if cfg!(target_os = "windows") {
        "windows".into()
    } else if cfg!(target_os = "linux") {
        "linux".into()
    } else {
        "unknown".into()
    }
}

fn resolve_tun_binary_path(app: &AppHandle) -> Result<PathBuf, String> {
    let bin = if cfg!(windows) {
        "tun2socks.exe"
    } else {
        "tun2socks"
    };

    if let Ok(p) = std::env::var("NEXRAY_TUN2SOCKS_BIN") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Ok(path);
        }
    }

    let resource_dir = app.path().resource_dir().map_err(|e| e.to_string())?;
    let resource_root = resource_dir.join("binaries");
    let bundled = resource_root.join(bin);
    if bundled.exists() {
        return Ok(bundled);
    }
    if let Some(p) = find_in_subdirs(&resource_root, bin) {
        return Ok(p);
    }

    let dev_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("binaries");
    let dev = dev_root.join(bin);
    if dev.exists() {
        return Ok(dev);
    }
    if let Some(p) = find_in_subdirs(&dev_root, bin) {
        return Ok(p);
    }

    if let Some(p) = find_on_path(bin) {
        return Ok(p);
    }

    Ok(bundled)
}

fn disabled_tun() -> TunStatus {
    TunStatus {
        state: TunState::Disabled,
        interface_name: None,
        since_ms: None,
        last_error: None,
    }
}

// ---------------------------------------------------------------------------
// Phase 5 — routing
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn routing_get(state: State<'_, AppState>) -> Result<RoutingSettings, String> {
    Ok(state.routing.lock().map_err(|e| e.to_string())?.clone())
}

#[tauri::command]
pub async fn routing_set(
    req: SetRoutingRequest,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<RoutingSettings, String> {
    {
        let mut guard = state.routing.lock().map_err(|e| e.to_string())?;
        *guard = req.settings.clone();
    }
    persist_routing(&app, &state)?;
    Ok(req.settings)
}

// ---------------------------------------------------------------------------
// Rules file (Shadowrocket-format default.conf)
// ---------------------------------------------------------------------------

/// The bundled default rules file is baked into the binary at build time so
/// we don't depend on Tauri resource resolution for first-launch copy.
const DEFAULT_RULES_CONF: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../conf/default.conf"));

const RULES_CONF_FILENAME: &str = "rules.conf";

#[tauri::command]
pub async fn rules_file_get(app: AppHandle) -> Result<String, String> {
    let path = rules_conf_path(&app)?;
    if !path.exists() {
        ensure_rules_file(&app)?;
    }
    std::fs::read_to_string(&path).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn rules_file_set(app: AppHandle, contents: String) -> Result<(), String> {
    // Validate by parsing — we don't reject malformed content, but we do
    // reject empty input so an accidental clear doesn't blow away the user's
    // rules. Fully-empty content is replaced by the bundled default.
    let to_write = if contents.trim().is_empty() {
        DEFAULT_RULES_CONF.to_string()
    } else {
        contents
    };
    let _ = rules_conf::parse(&to_write);
    let path = rules_conf_path(&app)?;
    let dir = path.parent().ok_or_else(|| "no parent dir".to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(&path, to_write).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn rules_file_append(
    app: AppHandle,
    matcher_type: String,
    matcher: String,
    destination: String,
    no_resolve: bool,
) -> Result<(), String> {
    use nexray_core::rules_conf::{ParsedRule, RuleKind};
    let policy = match destination.to_lowercase().as_str() {
        "direct" => nexray_core::RoutingDestination::Direct,
        "proxy" => nexray_core::RoutingDestination::Proxy,
        "block" => nexray_core::RoutingDestination::Block,
        other => return Err(format!("unknown destination: {other}")),
    };
    let kind = match matcher_type.to_lowercase().as_str() {
        "domain" => RuleKind::Domain(matcher.clone()),
        "domain-suffix" => RuleKind::DomainSuffix(matcher.clone()),
        "domain-keyword" => RuleKind::DomainKeyword(matcher.clone()),
        "domain-regex" => RuleKind::DomainRegex(matcher.clone()),
        "ip-cidr" => RuleKind::IpCidr(matcher.clone()),
        "ip-cidr6" => RuleKind::IpCidr6(matcher.clone()),
        "geoip" => RuleKind::Geoip(matcher.clone()),
        "ip-asn" => RuleKind::IpAsn(matcher.clone()),
        "user-agent" => RuleKind::UserAgent(matcher.clone()),
        "final" => RuleKind::Final,
        other => return Err(format!("unknown matcher type: {other}")),
    };
    let new_rule = ParsedRule {
        kind,
        policy,
        no_resolve,
        enabled: true,
    };
    let path = rules_conf_path(&app)?;
    if !path.exists() {
        ensure_rules_file(&app)?;
    }
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut conf = rules_conf::parse(&text);
    conf.append_rule(new_rule);
    let rendered = rules_conf::render(&conf);
    std::fs::write(&path, rendered).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn rules_file_set_enabled(
    app: AppHandle,
    rule_index: u32,
    enabled: bool,
) -> Result<(), String> {
    let path = rules_conf_path(&app)?;
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut conf = rules_conf::parse(&text);
    conf.set_rule_enabled(rule_index as usize, enabled);
    std::fs::write(&path, rules_conf::render(&conf)).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn rules_file_delete(app: AppHandle, rule_index: u32) -> Result<(), String> {
    let path = rules_conf_path(&app)?;
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut conf = rules_conf::parse(&text);
    conf.delete_rule(rule_index as usize);
    std::fs::write(&path, rules_conf::render(&conf)).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn rules_file_set_destination(
    app: AppHandle,
    rule_index: u32,
    destination: String,
) -> Result<(), String> {
    let dest = match destination.to_lowercase().as_str() {
        "direct" => nexray_core::RoutingDestination::Direct,
        "proxy" => nexray_core::RoutingDestination::Proxy,
        "block" => nexray_core::RoutingDestination::Block,
        other => return Err(format!("unknown destination: {other}")),
    };
    let path = rules_conf_path(&app)?;
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut conf = rules_conf::parse(&text);
    conf.set_rule_destination(rule_index as usize, dest);
    std::fs::write(&path, rules_conf::render(&conf)).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn rules_file_reset(app: AppHandle) -> Result<(), String> {
    let path = rules_conf_path(&app)?;
    let dir = path.parent().ok_or_else(|| "no parent dir".to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(&path, DEFAULT_RULES_CONF).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn rules_conf_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(dir.join(RULES_CONF_FILENAME))
}

pub fn ensure_rules_file(app: &AppHandle) -> Result<(), String> {
    let path = rules_conf_path(app)?;
    if path.exists() {
        return Ok(());
    }
    let dir = path.parent().ok_or_else(|| "no parent dir".to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(&path, DEFAULT_RULES_CONF).map_err(|e| e.to_string())?;
    Ok(())
}

fn rules_file_read_translated(app: &AppHandle) -> Result<Vec<serde_json::Value>, String> {
    ensure_rules_file(app)?;
    let path = rules_conf_path(app)?;
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let conf = rules_conf::parse(&text);
    let translated = rules_conf::translate(&conf);
    Ok(translated.rules)
}

// ---------------------------------------------------------------------------
// Phase 7 — settings + about
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn settings_get(state: State<'_, AppState>) -> Result<AppSettings, String> {
    Ok(state.settings.lock().map_err(|e| e.to_string())?.clone())
}

#[tauri::command]
pub async fn settings_set(
    req: SetSettingsRequest,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<AppSettings, String> {
    {
        let mut guard = state.settings.lock().map_err(|e| e.to_string())?;
        *guard = req.settings.clone();
    }
    persist_settings(&app, &state)?;
    Ok(req.settings)
}

#[tauri::command]
pub async fn app_info(_app: AppHandle) -> Result<AppInfo, String> {
    Ok(AppInfo {
        name: env!("CARGO_PKG_NAME").into(),
        version: env!("CARGO_PKG_VERSION").into(),
        platform: current_platform(),
    })
}

// ---------------------------------------------------------------------------
// Persistence helpers (tauri-plugin-store backed)
// ---------------------------------------------------------------------------

const STORE_FILE: &str = "subscriptions.json";
const SUBS_KEY: &str = "subscriptions";
const ROUTING_FILE: &str = "routing.json";
const ROUTING_KEY: &str = "routing";
const SETTINGS_FILE: &str = "settings.json";
const SETTINGS_KEY: &str = "settings";

pub fn load_subscriptions(app: &AppHandle, state: &AppState) -> Result<(), String> {
    use tauri_plugin_store::StoreExt;
    let store = app.store(STORE_FILE).map_err(|e| e.to_string())?;
    if let Some(raw) = store.get(SUBS_KEY) {
        let parsed: Vec<Subscription> = serde_json::from_value(raw.clone()).unwrap_or_default();
        let mut guard = state.subscriptions.lock().map_err(|e| e.to_string())?;
        for sub in parsed {
            guard.insert(sub.id.clone(), sub);
        }
    }
    Ok(())
}

pub fn load_routing(app: &AppHandle, state: &AppState) -> Result<(), String> {
    use tauri_plugin_store::StoreExt;
    let store = app.store(ROUTING_FILE).map_err(|e| e.to_string())?;
    if let Some(raw) = store.get(ROUTING_KEY) {
        if let Ok(parsed) = serde_json::from_value::<RoutingSettings>(raw.clone()) {
            *state.routing.lock().map_err(|e| e.to_string())? = parsed;
        }
    }
    Ok(())
}

pub fn load_settings(app: &AppHandle, state: &AppState) -> Result<(), String> {
    use tauri_plugin_store::StoreExt;
    let store = app.store(SETTINGS_FILE).map_err(|e| e.to_string())?;
    if let Some(raw) = store.get(SETTINGS_KEY) {
        if let Ok(parsed) = serde_json::from_value::<AppSettings>(raw.clone()) {
            *state.settings.lock().map_err(|e| e.to_string())? = parsed;
        }
    }
    Ok(())
}

fn persist_settings(app: &AppHandle, state: &State<'_, AppState>) -> Result<(), String> {
    use tauri_plugin_store::StoreExt;
    let store = app.store(SETTINGS_FILE).map_err(|e| e.to_string())?;
    let snapshot = state.settings.lock().map_err(|e| e.to_string())?.clone();
    store.set(
        SETTINGS_KEY,
        serde_json::to_value(&snapshot).map_err(|e| e.to_string())?,
    );
    store.save().map_err(|e| e.to_string())?;
    Ok(())
}

fn persist_routing(app: &AppHandle, state: &State<'_, AppState>) -> Result<(), String> {
    use tauri_plugin_store::StoreExt;
    let store = app.store(ROUTING_FILE).map_err(|e| e.to_string())?;
    let snapshot = state.routing.lock().map_err(|e| e.to_string())?.clone();
    store.set(
        ROUTING_KEY,
        serde_json::to_value(&snapshot).map_err(|e| e.to_string())?,
    );
    store.save().map_err(|e| e.to_string())?;
    Ok(())
}

fn persist(app: &AppHandle, state: &State<'_, AppState>) -> Result<(), String> {
    use tauri_plugin_store::StoreExt;
    let store = app.store(STORE_FILE).map_err(|e| e.to_string())?;
    let snapshot: Vec<Subscription> = state
        .subscriptions
        .lock()
        .map_err(|e| e.to_string())?
        .values()
        .cloned()
        .collect();
    store.set(
        SUBS_KEY,
        serde_json::to_value(&snapshot).map_err(|e| e.to_string())?,
    );
    store.save().map_err(|e| e.to_string())?;
    Ok(())
}
