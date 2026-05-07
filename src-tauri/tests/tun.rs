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

/// Bypass per-launch admin elevation so tests don't pop a Touch ID prompt.
/// Production paths leave this unset; only tests opt out.
fn no_elevation() {
    // SAFETY: tests are single-threaded with respect to env mutations during
    // setup, and this var is read at spawn time only.
    unsafe { std::env::set_var("NEXRAY_TUN_NO_ELEVATION", "1") };
}

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

fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut f: F) -> bool {
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
    no_elevation();
    let sup = TunSupervisor::new(stub_path().clone());
    assert_eq!(sup.status().state, TunState::Disabled);

    sup.enable("127.0.0.1:10808", "nexray-tun", &[])
        .expect("enable");

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
    no_elevation();
    let sup = TunSupervisor::new(stub_path().clone());
    sup.enable("127.0.0.1:10808", "nexray-tun", &[])
        .expect("enable");
    assert!(wait_until(Duration::from_secs(3), || sup.status().state
        == TunState::Active));
    let err = sup.enable("127.0.0.1:10808", "nexray-tun", &[]);
    assert!(err.is_err());
    let _ = sup.disable();
}

#[test]
fn missing_binary_returns_failed_state_and_error() {
    no_elevation();
    let path = PathBuf::from("/no/such/tun2socks");
    let sup = TunSupervisor::new(path.clone());
    let err = sup.enable("127.0.0.1:10808", "nexray-tun", &[]);
    assert!(err.is_err());
    let s = sup.status();
    assert_eq!(s.state, TunState::Failed);
    assert!(s.last_error.is_some());
}

#[test]
fn drop_terminates_child() {
    no_elevation();
    {
        let sup = TunSupervisor::new(stub_path().clone());
        sup.enable("127.0.0.1:10808", "nexray-tun", &[])
            .expect("enable");
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
    no_elevation();
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
    sup.enable("127.0.0.1:10808", "utun8", &[]).expect("enable");

    assert!(
        wait_until(Duration::from_secs(5), || sup.status().state
            == TunState::Failed),
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
    no_elevation();
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
    sup.enable("127.0.0.1:10808", "nexray-tun", &[])
        .expect("enable");

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

/// Cloning the supervisor must not call `disable()`. The supervisor is
/// `Clone` so it can be returned from each IPC handler, and every IPC
/// handler drops its clone on return — if Drop is on the wrapper instead
/// of the inner Arc, every IPC call after enable() teardown the freshly-
/// spawned tun2socks. Caught the hard way live on macOS.
#[test]
fn cloning_supervisor_does_not_disable_running_child() {
    no_elevation();
    let sup = TunSupervisor::new(stub_path().clone());
    sup.enable("127.0.0.1:10808", "nexray-tun", &[])
        .expect("enable");
    assert!(wait_until(Duration::from_secs(3), || sup.status().state
        == TunState::Active));

    // Clone-and-drop a few times — IPC pattern.
    for _ in 0..3 {
        let clone = sup.clone();
        drop(clone);
    }

    // Original supervisor's child should still be Active.
    sleep(Duration::from_millis(200));
    let s = sup.status();
    assert_eq!(
        s.state,
        TunState::Active,
        "clone-drop tore down the child; last_error={:?}",
        s.last_error
    );

    sup.disable().expect("disable");
}

/// Run the macOS launcher bash script directly (no osascript / no root) using
/// the long-running xray-stub as a stand-in for tun2socks. This validates the
/// detached-launcher contract: writes pidfile, runs binary, sigfile teardown
/// kills the process and removes the pidfile, log captures stderr.
#[cfg(target_os = "macos")]
#[test]
fn launcher_script_pidfile_and_sigfile_lifecycle() {
    use nexray::tun::{build_launcher_script, LauncherPaths};
    use std::process::Command;

    let dir = std::env::temp_dir().join(format!(
        "nexray-tun-script-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("mktemp dir");
    let script_path = dir.join("launcher.sh");
    let log_path = dir.join("tun.log");
    let pidfile_path = dir.join("tun.pid");
    let sigfile_path = dir.join("tun.sig");
    let iface_file_path = dir.join("tun.iface");

    let script = build_launcher_script(LauncherPaths {
        log: &log_path,
        pidfile: &pidfile_path,
        sigfile: &sigfile_path,
        binary: stub_path(),
        iface: "nexray-tun-test",
        socks_addr: "127.0.0.1:10808",
        bypass_ips: &[],
        iface_file: &iface_file_path,
        parent_pid: std::process::id(),
    });
    std::fs::write(&script_path, script).expect("write script");
    Command::new("chmod")
        .args(["+x"])
        .arg(&script_path)
        .status()
        .expect("chmod");

    // Run the launcher in the background as our user (no root). It loops
    // forever waiting on the sigfile.
    let mut child = Command::new("/bin/bash")
        .arg(&script_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn launcher");

    // The pidfile should appear within a couple of seconds.
    assert!(
        wait_until(Duration::from_secs(3), || pidfile_path.exists()),
        "pidfile never appeared"
    );
    let pid_str = std::fs::read_to_string(&pidfile_path).expect("read pidfile");
    let stub_pid: u32 = pid_str.trim().parse().expect("pidfile is numeric");
    assert!(stub_pid > 1);

    // The stub should be alive.
    let alive = Command::new("/bin/ps")
        .args(["-p", &stub_pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("ps");
    assert!(alive.success(), "stub process not alive");

    // Touch sigfile → launcher should kill the stub and remove the pidfile.
    std::fs::write(&sigfile_path, b"stop").expect("write sigfile");
    assert!(
        wait_until(Duration::from_secs(3), || !pidfile_path.exists()),
        "pidfile not cleaned up after sigfile"
    );

    // Launcher itself should exit shortly after.
    let _ = wait_until(Duration::from_secs(3), || {
        child.try_wait().ok().flatten().is_some()
    });
    let _ = child.kill();
    let _ = child.wait();

    // Stub PID is gone.
    let still_alive = Command::new("/bin/ps")
        .args(["-p", &stub_pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(!still_alive, "stub process leaked");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Parent-death watchdog: when the host (nexray) process dies without
/// touching the sigfile (Ctrl+C, SIGKILL, panic), the launcher must still
/// detect that and tear itself down. Simulates by spawning a "fake parent"
/// shell, telling the launcher to watch IT, then killing the fake parent.
/// Without this fix the user would lose internet on every Ctrl+C of the
/// dev server.
#[cfg(target_os = "macos")]
#[test]
fn launcher_tears_down_when_parent_dies() {
    use nexray::tun::{build_launcher_script, LauncherPaths};
    use std::process::Command;

    let dir = std::env::temp_dir().join(format!(
        "nexray-tun-pdeath-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("mktemp dir");
    let script_path = dir.join("launcher.sh");
    let log_path = dir.join("tun.log");
    let pidfile_path = dir.join("tun.pid");
    let sigfile_path = dir.join("tun.sig");
    let iface_file_path = dir.join("tun.iface");

    // Spawn a fake parent — `sleep 60` — that we can kill mid-test.
    let mut fake_parent = Command::new("/bin/sleep")
        .arg("60")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn fake parent");
    let fake_parent_pid = fake_parent.id();

    let script = build_launcher_script(LauncherPaths {
        log: &log_path,
        pidfile: &pidfile_path,
        sigfile: &sigfile_path,
        binary: stub_path(),
        iface: "nexray-tun-test",
        socks_addr: "127.0.0.1:10808",
        bypass_ips: &[],
        iface_file: &iface_file_path,
        parent_pid: fake_parent_pid,
    });
    std::fs::write(&script_path, script).expect("write script");
    Command::new("chmod")
        .args(["+x"])
        .arg(&script_path)
        .status()
        .expect("chmod");

    let mut launcher = Command::new("/bin/bash")
        .arg(&script_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn launcher");

    // Wait until launcher has the stub running and has written the pidfile.
    assert!(
        wait_until(Duration::from_secs(3), || pidfile_path.exists()),
        "pidfile never appeared"
    );

    // Kill the fake parent. Launcher should notice within ~300ms via
    // `kill -0 $PARENT_PID` and tear down without us ever touching the
    // sigfile.
    let _ = fake_parent.kill();
    let _ = fake_parent.wait();

    assert!(
        wait_until(Duration::from_secs(3), || !pidfile_path.exists()),
        "launcher didn't clean up pidfile after parent died"
    );

    // Launcher itself should exit shortly after.
    let _ = wait_until(Duration::from_secs(3), || {
        launcher.try_wait().ok().flatten().is_some()
    });
    let _ = launcher.kill();
    let _ = launcher.wait();

    // Confirm the log mentions the parent_died trigger so we know it was
    // the watchdog that fired, not the sigfile branch we never touched.
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        log.contains("parent_died"),
        "expected 'parent_died' shutdown trigger in log, got:\n{log}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
