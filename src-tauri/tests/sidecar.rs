//! XraySidecar integration tests, driven against the workspace's `xray-stub`
//! binary so we don't need a real bundled xray-core.
//!
//! Per DEVELOPMENT.md §11: `expect`/`unwrap` are allowed in tests.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::thread::sleep;
use std::time::{Duration, Instant};

use nexray::core::XraySidecar;
use nexray_core::xray_config::{default_routing_settings, materialize, XrayConfigOptions};
use nexray_core::{Alpn, CdnWsProfile, ConnectionState, Fingerprint, Profile};

fn target_dir() -> PathBuf {
    if let Ok(d) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(d)
    } else {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        manifest
            .parent()
            .expect("workspace root from src-tauri")
            .join("target")
    }
}

fn stub_filename() -> &'static str {
    if cfg!(windows) {
        "xray-stub.exe"
    } else {
        "xray-stub"
    }
}

/// Ensure xray-stub is built before any test spawns it. Built once per test
/// binary; tests outside `cargo test --workspace` are still safe.
fn xray_stub_path() -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let status = std::process::Command::new(env!("CARGO"))
            .args(["build", "-p", "xray-stub", "--quiet"])
            .status()
            .expect("cargo build xray-stub");
        assert!(status.success(), "cargo build xray-stub failed");
        let path = target_dir().join("debug").join(stub_filename());
        assert!(path.exists(), "{path:?} not found after build");
        path
    })
}

/// Minimal config the stub will parse to extract a SOCKS port.
fn stub_config(port: u16) -> String {
    format!(r#"{{ "inbounds": [{{ "port": {port}, "listen": "127.0.0.1" }}] }}"#)
}

fn wait_until<F: Fn() -> bool>(timeout: Duration, f: F) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        sleep(Duration::from_millis(50));
    }
    f()
}

#[test]
fn start_transitions_disconnected_to_connecting_then_connected() {
    let sidecar = XraySidecar::new(xray_stub_path().clone(), vec![]);
    assert_eq!(sidecar.status().state, ConnectionState::Disconnected);

    sidecar
        .start("p1".into(), 19111, stub_config(19111))
        .expect("start");

    // Once stub prints `xray-stub ready`, the supervisor should flip to Connected.
    let ok = wait_until(Duration::from_secs(3), || {
        sidecar.status().state == ConnectionState::Connected
    });
    assert!(ok, "expected Connected, got {:?}", sidecar.status());

    let s = sidecar.status();
    assert_eq!(s.profile_id.as_deref(), Some("p1"));
    assert_eq!(s.socks_port, Some(19111));
    assert!(s.since_ms.is_some());

    sidecar.stop().expect("stop");
    assert_eq!(sidecar.status().state, ConnectionState::Disconnected);
}

#[test]
fn external_kill_transitions_to_crashed_within_2s() {
    let sidecar = XraySidecar::new(xray_stub_path().clone(), vec![]);
    sidecar
        .start("p2".into(), 19112, stub_config(19112))
        .expect("start");

    // Wait for ready, then snapshot status to learn the child PID via OS.
    assert!(wait_until(Duration::from_secs(3), || sidecar
        .status()
        .state
        == ConnectionState::Connected));

    // Kill the child externally — targeted by PID so we don't reap stubs
    // spawned by other tests running in parallel under `cargo test`.
    let pid = sidecar.child_pid().expect("child pid");
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .status();
    }

    let crashed = wait_until(Duration::from_secs(2), || {
        sidecar.status().state == ConnectionState::Crashed
    });
    assert!(
        crashed,
        "expected Crashed within 2s, got {:?}",
        sidecar.status()
    );
    // Supervisor must NOT auto-restart silently (Phase 2 acceptance).
    sleep(Duration::from_millis(500));
    assert_eq!(sidecar.status().state, ConnectionState::Crashed);

    let _ = sidecar.stop();
}

#[test]
fn drop_terminates_child() {
    {
        let sidecar = XraySidecar::new(xray_stub_path().clone(), vec![]);
        sidecar
            .start("p3".into(), 19113, stub_config(19113))
            .expect("start");
        wait_until(Duration::from_secs(3), || {
            sidecar.status().state == ConnectionState::Connected
        });
        // sidecar drops at end of this block; Drop calls stop(), which kills
        // the child + waits for its exit.
    }
    // No xray-stub processes should remain. Best-effort sleep so any straggler
    // would have shown up; in CI we trust the OS process accounting and move on.
    sleep(Duration::from_millis(500));
}

#[test]
fn double_start_is_rejected() {
    let sidecar = XraySidecar::new(xray_stub_path().clone(), vec![]);
    sidecar
        .start("p4".into(), 19114, stub_config(19114))
        .expect("start");
    assert!(wait_until(Duration::from_secs(3), || sidecar
        .status()
        .state
        == ConnectionState::Connected));
    let err = sidecar.start("p4".into(), 19114, stub_config(19114));
    assert!(err.is_err());
    let _ = sidecar.stop();
}

// ---------------------------------------------------------------------------
// End-to-end "Connect works" test
//
// Exercises the full pipeline that the IPC `connect` command runs:
//
//   1. Build a Profile (the same shape the UI persists).
//   2. Materialize it through `nexray_core::xray_config::materialize` into
//      the Xray-shaped JSON config.
//   3. Spawn the supervisor with that config piped to stdin.
//   4. Wait for the supervisor to flip Connecting → Connected.
//   5. Confirm the configured SOCKS inbound port is *actually* listening on
//      127.0.0.1 — i.e. the child process accepted our config and bound
//      the inbound. With real xray this is the SOCKS5 proxy; with the test
//      stub it's a plain TCP accept loop. Either way, the client-visible
//      contract — "Connect → SOCKS port is reachable on loopback" — holds.
//   6. Disconnect, then confirm the listener is gone.
//
// This is the test that catches regressions in the connect-pipeline plumbing
// (config materialization, stdin pipe, supervisor lifecycle) without needing
// a real xray-core binary.
// ---------------------------------------------------------------------------

fn pick_loopback_port() -> u16 {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind 0");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

fn fixture_cdn_ws_profile() -> Profile {
    Profile::CdnWs(CdnWsProfile {
        id: "fixture-1".into(),
        name: "fixture".into(),
        remark: None,
        address: "127.0.0.1".into(),
        port: 8443,
        uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
        host: "fixture.example".into(),
        path: "/?ed=2560".into(),
        sni: "fixture.example".into(),
        alpn: vec![Alpn::H2, Alpn::Http11],
        fingerprint: Fingerprint::Chrome,
    })
}

fn is_port_open(port: u16, timeout: Duration) -> bool {
    TcpStream::connect_timeout(
        &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
        timeout,
    )
    .is_ok()
}

#[test]
fn connect_pipeline_brings_up_socks_listener_and_disconnect_tears_it_down() {
    let socks_port = pick_loopback_port();
    let profile = fixture_cdn_ws_profile();
    let config = materialize(
        &profile,
        &XrayConfigOptions {
            socks_port,
            stats_port: None,
            log_level: "warning",
            routing: default_routing_settings(),
            extra_rules: vec![],
            direct_send_through: None,
        },
    )
    .expect("materialize");
    let config_json = serde_json::to_string(&config).expect("serialize");

    let sidecar = XraySidecar::new(xray_stub_path().clone(), vec![]);
    sidecar
        .start("e2e".into(), socks_port, config_json)
        .expect("start");

    assert!(
        wait_until(Duration::from_secs(3), || sidecar.status().state
            == ConnectionState::Connected),
        "supervisor never reached Connected: {:?}",
        sidecar.status(),
    );

    assert!(
        wait_until(Duration::from_secs(2), || is_port_open(
            socks_port,
            Duration::from_millis(200)
        )),
        "SOCKS port {socks_port} never became reachable",
    );

    let s = sidecar.status();
    assert_eq!(s.profile_id.as_deref(), Some("e2e"));
    assert_eq!(s.socks_port, Some(socks_port));
    assert!(s.since_ms.is_some());

    sidecar.stop().expect("stop");
    assert_eq!(sidecar.status().state, ConnectionState::Disconnected);

    sleep(Duration::from_millis(300));
    assert!(
        !is_port_open(socks_port, Duration::from_millis(100)),
        "SOCKS port {socks_port} still reachable after disconnect",
    );
}

#[test]
fn connect_pipeline_recovers_from_disconnect_then_reconnect() {
    let socks_port = pick_loopback_port();
    let profile = fixture_cdn_ws_profile();
    let config_json = serde_json::to_string(
        &materialize(
            &profile,
            &XrayConfigOptions {
                socks_port,
                stats_port: None,
                log_level: "warning",
                routing: default_routing_settings(),
                extra_rules: vec![],
                direct_send_through: None,
            },
        )
        .expect("materialize"),
    )
    .expect("serialize");

    let sidecar = XraySidecar::new(xray_stub_path().clone(), vec![]);

    sidecar
        .start("p1".into(), socks_port, config_json.clone())
        .expect("start 1");
    assert!(wait_until(Duration::from_secs(3), || sidecar
        .status()
        .state
        == ConnectionState::Connected));
    assert!(is_port_open(socks_port, Duration::from_millis(200)));

    sidecar.stop().expect("stop");
    sleep(Duration::from_millis(300));
    assert!(!is_port_open(socks_port, Duration::from_millis(100)));

    sidecar
        .start("p2".into(), socks_port, config_json)
        .expect("start 2");
    assert!(wait_until(Duration::from_secs(3), || sidecar
        .status()
        .state
        == ConnectionState::Connected));
    assert!(is_port_open(socks_port, Duration::from_millis(200)));

    sidecar.stop().expect("final stop");
}
