//! Library entrypoint for the Tauri shell.
//!
//! Exposed as a library so integration tests under `src-tauri/tests/` can
//! reach into `nexray::core::XraySidecar` etc. The real desktop binary is
//! `src/main.rs` which delegates to `run()` here.

pub mod commands;
pub mod config;
pub mod core;
pub mod proxy;
pub mod runtime;
pub mod scheduler;
pub mod state;
pub mod stats;
pub mod subscription;
pub mod tray;
pub mod tun;

pub use crate::core::XraySidecar;

// Per DEVELOPMENT.md §11: `unwrap`/`expect` are allowed in `main` and tests.
// `run` IS the moral equivalent of `main` for the bundled binary.
#[allow(clippy::expect_used)]
pub fn run() {
    use tauri::Manager;
    // Default to `info` level so users see spawn + supervisor logs without
    // needing to set RUST_LOG. Override as usual:
    //   RUST_LOG=debug,xray=trace pnpm tauri dev
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(state::AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::ping,
            commands::connect,
            commands::disconnect,
            commands::status,
            commands::traffic_stats,
            commands::subscriptions_list,
            commands::subscription_add,
            commands::subscription_delete,
            commands::subscription_refresh,
            commands::pool_list,
            commands::pool_probe_all,
            commands::routing_get,
            commands::routing_set,
            commands::tun_capabilities,
            commands::tun_status,
            commands::tun_enable,
            commands::tun_disable,
            commands::system_proxy_status,
            commands::system_proxy_enable,
            commands::system_proxy_disable,
            commands::settings_get,
            commands::settings_set,
            commands::app_info,
            commands::rules_file_get,
            commands::rules_file_set,
            commands::rules_file_append,
            commands::rules_file_set_enabled,
            commands::rules_file_set_destination,
            commands::rules_file_delete,
            commands::rules_file_reset,
        ])
        .setup(|app| {
            tray::install(app)?;
            // Self-heal: kill any orphan xray / tun2socks children left
            // behind by a previous unclean shutdown, then hydrate from disk
            // and start the auto-refresh task.
            let handle = app.handle().clone();
            runtime::scrub_orphans(&handle);
            let state = app.state::<state::AppState>();
            let _ = commands::load_subscriptions(&handle, &state);
            let _ = commands::load_routing(&handle, &state);
            let _ = commands::load_settings(&handle, &state);
            // First-launch copy of default.conf into app data.
            let _ = commands::ensure_rules_file(&handle);
            scheduler::spawn(handle.clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
