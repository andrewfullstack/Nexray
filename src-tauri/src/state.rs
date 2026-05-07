//! App-level shared state. The Tauri runtime hands a `&State<AppState>` to
//! every command, so all commands talk to the same `XraySidecar`.

use std::collections::HashMap;
use std::sync::Mutex;

use nexray_core::xray_config::default_routing_settings;
use nexray_core::{AppSettings, RoutingSettings, Subscription};

use nexray_core::Profile;

use crate::core::XraySidecar;
use crate::subscription::ProbeRecord;

pub struct AppState {
    /// Lazily constructed once we resolve the bundled xray-core binary path.
    /// `None` until the first `connect` call.
    pub sidecar: Mutex<Option<XraySidecar>>,
    /// The profile currently fed to the sidecar. Set by `connect`, cleared
    /// by `disconnect`. Used by `tun_enable` to learn the proxy server's
    /// address so we can install bypass routes; the connect path doesn't
    /// always go through `subscriptions` (paste-link is direct), so we
    /// can't recover this from there.
    pub active_profile: Mutex<Option<Profile>>,
    /// Loopback port the running xray's stats inbound is bound to. Picked
    /// fresh in `connect` (and again on every routing/rules-file
    /// hot-reload), cleared on disconnect. The `traffic_stats` IPC reads
    /// this to shell out to `xray api statsquery`.
    pub stats_port: Mutex<Option<u16>>,
    /// Active subscriptions keyed by `Subscription::id`. Persisted via
    /// `tauri-plugin-store` under `subscriptions.json`.
    pub subscriptions: Mutex<HashMap<String, Subscription>>,
    /// Latest TCP-connect latency per profile id.
    pub probes: Mutex<HashMap<String, ProbeRecord>>,
    /// Active routing preset + custom rules + DNS. Persisted via
    /// `tauri-plugin-store` under `routing.json`.
    pub routing: Mutex<RoutingSettings>,
    /// TUN supervisor — lazily constructed when the user first enables TUN.
    pub tun: Mutex<Option<crate::tun::TunSupervisor>>,
    /// App-wide settings (auto-update opt-in). Persisted via
    /// `tauri-plugin-store` under `settings.json`.
    pub settings: Mutex<AppSettings>,
    /// macOS / Windows / Linux system-proxy supervisor. Process-lifetime
    /// only — the OS proxy state is restored on app exit via Drop.
    pub system_proxy: crate::proxy::ProxySupervisor,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            sidecar: Mutex::new(None),
            active_profile: Mutex::new(None),
            stats_port: Mutex::new(None),
            subscriptions: Mutex::new(HashMap::new()),
            probes: Mutex::new(HashMap::new()),
            routing: Mutex::new(default_routing_settings()),
            tun: Mutex::new(None),
            settings: Mutex::new(AppSettings {
                auto_update_opt_in: false,
            }),
            system_proxy: crate::proxy::ProxySupervisor::default(),
        }
    }
}
