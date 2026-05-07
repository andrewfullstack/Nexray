//! TunSupervisor lifecycle tests, driven against the workspace's `xray-stub`
//! binary (which behaves the same way tun2socks would for FSM purposes:
//! starts, prints to stderr, sleeps until killed).
//!
//! Per DEVELOPMENT.md §11: `expect`/`unwrap` are allowed in tests.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::OnceLock;
use std::thread::sleep;
use std::time::{Duration, Instant};

use nexray::tun::TunSupervisor;
use nexray_core::TunState;

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

fn stub_path() -> &'static PathBuf {
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
fn enable_transitions_disabled_to_starting_then_active() {
    let sup = TunSupervisor::new(stub_path().clone());
    assert_eq!(sup.status().state, TunState::Disabled);

    sup.enable("127.0.0.1:10808", "nexray-tun").expect("enable");

    assert!(wait_until(Duration::from_secs(3), || sup.status().state
        == TunState::Active));
    let s = sup.status();
    assert_eq!(s.interface_name.as_deref(), Some("nexray-tun"));
    assert!(s.since_ms.is_some());

    sup.disable().expect("disable");
    assert_eq!(sup.status().state, TunState::Disabled);
}

#[test]
fn double_enable_is_rejected() {
    let sup = TunSupervisor::new(stub_path().clone());
    sup.enable("127.0.0.1:10808", "nexray-tun").expect("enable");
    assert!(wait_until(Duration::from_secs(3), || sup.status().state
        == TunState::Active));
    let err = sup.enable("127.0.0.1:10808", "nexray-tun");
    assert!(err.is_err());
    let _ = sup.disable();
}

#[test]
fn missing_binary_returns_failed_state_and_error() {
    let path = PathBuf::from("/no/such/tun2socks");
    let sup = TunSupervisor::new(path.clone());
    let err = sup.enable("127.0.0.1:10808", "nexray-tun");
    assert!(err.is_err());
    let s = sup.status();
    assert_eq!(s.state, TunState::Failed);
    assert!(s.last_error.is_some());
}

#[test]
fn drop_terminates_child() {
    {
        let sup = TunSupervisor::new(stub_path().clone());
        sup.enable("127.0.0.1:10808", "nexray-tun").expect("enable");
        wait_until(Duration::from_secs(3), || {
            sup.status().state == TunState::Active
        });
        // sup drops here; Drop calls disable() which kills the child.
    }
    sleep(Duration::from_millis(500));
}

/// End-to-end with the real tun2socks binary, if present in the dev workspace.
/// Without root we can only reach the privilege-failure path — but that's
/// exactly what we want to confirm: spawn → stderr drain → sticky FATAL line
/// → Failed state → annotated `last_error`. Gated on the binary's presence so
/// CI on machines without the unzip works fine.
#[cfg(target_os = "macos")]
#[test]
fn real_tun2socks_unprivileged_fails_with_annotated_error() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Match the resolver: binaries/<subdir>/tun2socks
    let candidate = manifest
        .join("binaries")
        .join("tun2socks-darwin-arm64")
        .join("tun2socks");
    if !candidate.exists() {
        eprintln!("skipping: real tun2socks not provisioned at {candidate:?}");
        return;
    }

    let sup = TunSupervisor::new(candidate);
    sup.enable("127.0.0.1:10808", "utun8").expect("enable");

    assert!(
        wait_until(Duration::from_secs(5), || sup.status().state == TunState::Failed),
        "expected Failed within 5s, got {:?}",
        sup.status().state
    );
    let s = sup.status();
    let err = s.last_error.expect("last_error captured");
    assert!(
        err.contains("operation not permitted"),
        "expected privilege-denied wording, got: {err}"
    );
    assert!(
        err.contains("admin/root") || err.contains("Phase-7"),
        "expected our annotation, got: {err}"
    );
}

/// Real tun2socks logs a FATAL line followed by Go-runtime stack frames before
/// exiting. The supervisor must surface the FATAL line in `last_error` — not
/// the trailing stack-trace tail. We simulate by spawning `/bin/sh -c`.
#[cfg(unix)]
#[test]
fn first_error_line_is_sticky_in_last_error() {
    use std::process::Command;

    // Write a tiny shell script as the "binary" so the supervisor spawns it
    // by absolute path. The script ignores its args, prints a FATAL line +
    // stack-trace tail to stderr, then exits non-zero.
    let dir = std::env::temp_dir().join(format!("nexray-tun-stub-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mktemp dir");
    let script = dir.join("fake-tun2socks.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\n\
         echo 'FATAL engine/engine.go:45 [ENGINE] failed to start: create tun: operation not permitted' 1>&2\n\
         echo 'github.com/xjasonlyu/tun2socks/v2/engine.Start' 1>&2\n\
         echo '    github.com/xjasonlyu/tun2socks/v2/engine/engine.go:45' 1>&2\n\
         echo 'runtime.main' 1>&2\n\
         echo '    runtime/proc.go:272' 1>&2\n\
         exit 1\n",
    )
    .expect("write script");
    Command::new("chmod")
        .args(["+x"])
        .arg(&script)
        .status()
        .expect("chmod");

    let sup = TunSupervisor::new(script.clone());
    sup.enable("127.0.0.1:10808", "nexray-tun").expect("enable");

    // Wait for the child to exit and the next status() poll to flip to Failed.
    assert!(wait_until(Duration::from_secs(3), || sup.status().state
        == TunState::Failed));
    let s = sup.status();
    let err = s.last_error.expect("last_error captured");
    assert!(
        err.contains("operation not permitted"),
        "expected sticky FATAL line, got: {err}"
    );
    assert!(
        !err.contains("proc.go"),
        "stack-trace tail leaked into last_error: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
