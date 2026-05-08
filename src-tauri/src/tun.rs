//! TUN-mode supervisor — Phase 6.
//!
//! Spawns the bundled `tun2socks` binary with the SOCKS inbound endpoint of
//! our xray sidecar so OS-level traffic flows through the proxy. Mirrors the
//! `XraySidecar` lifecycle shape (start / stop / status, Drop kills the child)
//! so the IPC layer can poll uniformly.
//!
//! ### Privilege escalation
//!
//! tun2socks needs admin rights to create the kernel interface and rewrite
//! routes. Phase 6 ships a per-launch elevation:
//!
//! - **macOS** — wrap the spawn in `osascript do shell script ... with
//!   administrator privileges`. macOS shows a native Touch ID/password
//!   prompt; the inner shell backgrounds tun2socks (echoing its PID to
//!   stdout so we can track it), then polls a sigfile so teardown only
//!   needs *one* prompt per session.
//! - **Linux** — wrap the spawn in `pkexec`, which polkit displays as a
//!   graphical auth dialog (or TTY prompt under SSH). The launcher script
//!   uses `ip route` / `ip addr` to install the same split-default routing
//!   the macOS path uses, plus per-host bypass routes for the proxy
//!   server's IP so xray's upstream connection doesn't loop back through
//!   the tunnel. Falls back to direct (unprivileged) spawn — which then
//!   surfaces the EPERM error to the user — when `pkexec` isn't installed.
//! - **Windows** — wrap the spawn in `powershell -Command "Start-Process …
//!   -Verb RunAs -Wait"`, which triggers a UAC consent dialog. The
//!   elevated PowerShell launcher script uses `New-NetRoute` /
//!   `New-NetIPAddress` to bring up the Wintun adapter and install the
//!   same split-default routing the macOS/Linux paths use, plus per-host
//!   bypass routes. The outer (unprivileged) powershell waits on the
//!   elevated child for the full session, so disable() can SIGTERM it to
//!   bring everything down.
//!
//! The proper persistent-helper approach (`SMAppService` on macOS,
//! `NetworkExtension` on macOS for App Store distribution, polkit policy
//! file on Linux, scheduled-task helper on Windows) is Phase 7+ — see
//! `docs/MACOS_VPN.md`.
//!
//! Tests bypass elevation by setting `NEXRAY_TUN_NO_ELEVATION=1` so the
//! supervisor's FSM can be exercised without prompting humans.
//!
//! ### Route management
//!
//! tun2socks itself sets up the interface address and brings it up. The
//! default-route swap (so all traffic captures) is handled per-OS by
//! tun2socks's `-tunRoute` flag. We don't shell out to `route` ourselves —
//! that responsibility lives in tun2socks.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use nexray_core::{TunState, TunStatus};
use thiserror::Error;

#[derive(Clone)]
pub struct TunSupervisor {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    binary_path: PathBuf,
    state: TunState,
    /// The process we directly spawned. On Linux/Windows it's tun2socks
    /// itself. On macOS it's `osascript`, which exits immediately after
    /// auth (the launcher is detached) — so this is `None` after the
    /// brief enable() bring-up window on that platform.
    launcher: Option<Child>,
    /// macOS only — the PID of the privileged tun2socks child. We can't
    /// signal it from this UID, so teardown writes to `sigfile` instead.
    privileged_pid: Option<u32>,
    /// macOS only — path to the teardown sigfile. `disable()` creates it,
    /// the launcher script's poll loop notices and sends SIGTERM.
    sigfile: Option<PathBuf>,
    /// macOS only — path to the per-session pidfile written by the
    /// detached launcher. Its disappearance signals the privileged
    /// tun2socks has exited.
    privileged_pidfile: Option<PathBuf>,
    /// macOS only — path to the per-session log file. Tailed by a
    /// background thread so live tun2socks errors flow into `last_error`.
    log_path: Option<PathBuf>,
    interface_name: Option<String>,
    since_ms: Option<u64>,
    last_error: Option<String>,
    pid_file: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN supervisor already active; call disable first")]
    AlreadyActive,
    #[error("tun2socks binary not bundled at {0}")]
    BinaryMissing(PathBuf),
    #[error("failed to spawn tun2socks: {0}")]
    Spawn(std::io::Error),
}

impl TunSupervisor {
    pub fn new(binary_path: PathBuf) -> Self {
        let inner = Inner {
            binary_path,
            state: TunState::Disabled,
            launcher: None,
            privileged_pid: None,
            sigfile: None,
            privileged_pidfile: None,
            log_path: None,
            interface_name: None,
            since_ms: None,
            last_error: None,
            pid_file: None,
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub fn set_pid_file(&self, path: PathBuf) {
        lock(&self.inner).pid_file = Some(path);
    }

    /// Enable TUN by spawning tun2socks pointed at `socks_addr` (e.g.
    /// `127.0.0.1:10808`). On macOS this triggers the admin password
    /// prompt; the call returns once the user authorizes (or cancels).
    pub fn enable(
        &self,
        socks_addr: &str,
        iface_name: &str,
        bypass_ips: &[String],
    ) -> Result<TunStatus, TunError> {
        let mut inner = lock(&self.inner);
        if matches!(inner.state, TunState::Starting | TunState::Active) {
            return Err(TunError::AlreadyActive);
        }
        if !inner.binary_path.exists() {
            inner.state = TunState::Failed;
            inner.last_error = Some(format!(
                "tun2socks binary not found at {}",
                inner.binary_path.display()
            ));
            return Err(TunError::BinaryMissing(inner.binary_path.clone()));
        }

        let binary = inner.binary_path.clone();
        let sigfile = make_sigfile_path();
        let iface_owned = iface_name.to_string();

        let strategy = spawn_strategy(&binary, iface_name, socks_addr, &sigfile, bypass_ips)
            .map_err(TunError::Spawn)?;

        match strategy {
            SpawnedLauncher::Direct(mut child) => {
                // Linux/Windows path (also test-mode bypass). tun2socks itself
                // is our Child; stderr is the only stream.
                if let Some(stderr) = child.stderr.take() {
                    let inner_arc = Arc::clone(&self.inner);
                    std::thread::spawn(move || drain_lines(stderr, inner_arc, false));
                }
                let launcher_pid = child.id();
                inner.state = TunState::Starting;
                inner.launcher = Some(child);
                inner.sigfile = None;
                inner.privileged_pidfile = None;
                inner.log_path = None;
                inner.interface_name = Some(iface_owned);
                inner.since_ms = Some(now_ms());
                inner.last_error = None;
                if let Some(p) = inner.pid_file.as_ref() {
                    let _ = std::fs::write(p, launcher_pid.to_string());
                }
            }
            #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
            SpawnedLauncher::Privileged {
                mut child,
                pidfile,
                log_path,
                iface_file,
            } => {
                // Elevated path (osascript on macOS, pkexec on Linux). The
                // wrapper stays alive for the whole session: it presents
                // the password prompt, runs the launcher script as root,
                // and only exits when the launcher exits (which happens
                // via sigfile teardown). We poll the pidfile to learn
                // when tun2socks is up.
                //
                // Race window: the wrapper may fail (user cancelled the
                // auth prompt) before the pidfile appears. So we
                // interleave try_wait() with pidfile polling, with a
                // generous timeout to account for the human typing their
                // password.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                let pid_result = loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            // osascript already exited — pidfile may or
                            // may not exist. If it does, we caught it after
                            // a fast tun2socks crash; surface the log.
                            break Err(format!(
                                "elevation wrapper exited before pidfile appeared: {status}"
                            ));
                        }
                        Ok(None) => {}
                        Err(e) => break Err(format!("try_wait failed: {e}")),
                    }
                    if let Ok(s) = std::fs::read_to_string(&pidfile) {
                        if let Ok(pid) = s.trim().parse::<u32>() {
                            break Ok(pid);
                        }
                    }
                    if std::time::Instant::now() >= deadline {
                        break Err("timed out waiting for launcher pidfile (60s) — admin \
                             prompt not answered or launcher script never ran"
                            .into());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(150));
                };

                let pid = match pid_result {
                    Ok(pid) => pid,
                    Err(why) => {
                        // Best-effort: kill the wrapper so it doesn't
                        // hang around if the prompt was still up.
                        let _ = child.kill();
                        let _ = child.wait();
                        // Read the launcher log (where tun2socks's FATAL
                        // lines go) so we can log the diagnostic detail
                        // even though we surface a friendlier message
                        // to the UI.
                        let log_excerpt = std::fs::read_to_string(&log_path)
                            .ok()
                            .map(|s| {
                                s.lines()
                                    .rev()
                                    .take(8)
                                    .collect::<Vec<_>>()
                                    .into_iter()
                                    .rev()
                                    .collect::<Vec<_>>()
                                    .join(" | ")
                            })
                            .unwrap_or_else(|| "no log file".into());
                        // Diagnostic detail goes to tracing for debug
                        // builds / log files; the user-facing message in
                        // `last_error` is the short-form below. The most
                        // common path here is the user dismissing the
                        // sudo prompt (osascript exits with status 1 when
                        // auth is cancelled), so phrase the UI message
                        // around that.
                        tracing::warn!(
                            target: "tun",
                            "privileged bring-up failed: {why}; log tail: {log_excerpt}",
                        );
                        let msg = "TUN Start failed without auth".to_string();
                        inner.state = TunState::Failed;
                        inner.last_error = Some(msg.clone());
                        return Err(TunError::Spawn(std::io::Error::other(msg)));
                    }
                };

                // Spawn the log tailer so live FATAL lines flow into
                // last_error. Stops itself when the pidfile vanishes.
                let inner_arc = Arc::clone(&self.inner);
                let log_clone = log_path.clone();
                let pidfile_clone = pidfile.clone();
                std::thread::spawn(move || tail_log(&log_clone, &pidfile_clone, inner_arc));

                // Read the launcher's chosen iface (it may have iterated
                // past our hint if the device was busy).
                let actual_iface = std::fs::read_to_string(&iface_file)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or(iface_owned);

                inner.state = TunState::Active;
                inner.launcher = Some(child);
                inner.privileged_pid = Some(pid);
                inner.sigfile = Some(sigfile);
                inner.privileged_pidfile = Some(pidfile);
                inner.log_path = Some(log_path);
                inner.interface_name = Some(actual_iface);
                inner.since_ms = Some(now_ms());
                inner.last_error = None;
                if let Some(p) = inner.pid_file.as_ref() {
                    let _ = std::fs::write(p, pid.to_string());
                }
            }
        }
        Ok(snapshot(&inner))
    }

    pub fn disable(&self) -> Result<TunStatus, TunError> {
        let mut inner = lock(&self.inner);
        inner.state = TunState::Stopping;
        // macOS-detached path: touch sigfile so the launcher's poll loop
        // (running as root) sees it and SIGTERMs tun2socks. We don't have
        // the launcher Child handle anymore on this path.
        let pidfile = inner.privileged_pidfile.take();
        let sigfile = inner.sigfile.take();
        let log_path = inner.log_path.take();
        if let Some(sf) = sigfile.as_ref() {
            let _ = std::fs::write(sf, b"stop");
        }
        // Direct path: kill the Child we still own.
        if let Some(mut child) = inner.launcher.take() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if std::time::Instant::now() >= deadline => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
                    Err(_) => break,
                }
            }
        }
        inner.privileged_pid = None;
        if let Some(p) = inner.pid_file.as_ref() {
            let _ = std::fs::remove_file(p);
        }
        inner.state = TunState::Disabled;
        inner.interface_name = None;
        inner.since_ms = None;
        inner.last_error = None;
        // Wait briefly for the launcher pidfile to disappear (i.e. the
        // detached privileged loop exited cleanly). Drop the lock first so
        // status() can still be called concurrently.
        drop(inner);
        if let Some(pf) = pidfile.as_ref() {
            wait_for_path_gone(pf, std::time::Duration::from_secs(3));
        }
        // Best-effort temp file cleanup.
        if let Some(p) = pidfile {
            let _ = std::fs::remove_file(p);
        }
        if let Some(p) = log_path {
            let _ = std::fs::remove_file(p);
        }
        if let Some(p) = sigfile {
            let _ = std::fs::remove_file(p);
        }
        Ok(self.status())
    }

    pub fn status(&self) -> TunStatus {
        let mut inner = lock(&self.inner);
        // Direct path: launcher Child is the source of truth.
        if let Some(child) = inner.launcher.as_mut() {
            if let Ok(Some(status)) = child.try_wait() {
                inner.state = TunState::Failed;
                if inner.last_error.is_none() {
                    inner.last_error = Some(format!("tun2socks exited: {status}"));
                }
                inner.launcher = None;
                inner.privileged_pid = None;
            }
        }
        // macOS-detached path: the privileged pidfile is the source of
        // truth. If it's gone or its PID is no longer alive, the tunnel is
        // down — but distinguish "we asked for that" (Stopping/Disabled)
        // from "it crashed" (Failed).
        if let (Some(pid), Some(pidfile)) =
            (inner.privileged_pid, inner.privileged_pidfile.as_ref())
        {
            let alive = pidfile.exists() && process_alive(pid);
            if !alive
                && !matches!(
                    inner.state,
                    TunState::Stopping | TunState::Disabled | TunState::Failed
                )
            {
                inner.state = TunState::Failed;
                if inner.last_error.is_none() {
                    inner.last_error = Some("tun2socks exited unexpectedly".into());
                }
                inner.privileged_pid = None;
            }
        }
        snapshot(&inner)
    }
}

/// Cross-UID liveness check. `kill(pid, 0)` returns 0 on permission-OK,
/// EPERM if alive but root-owned (good — still alive), ESRCH if gone.
/// Without root-signal permission we shell out to `ps` which doesn't care
/// about the target's UID.
fn process_alive(pid: u32) -> bool {
    Command::new("/bin/ps")
        .args(["-p", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn wait_for_path_gone(path: &Path, timeout: std::time::Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if !path.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Drop is on `Inner`, NOT on `TunSupervisor`. The supervisor is cloned
/// every time it leaves an IPC handler (`pub struct TunSupervisor { inner:
/// Arc<Mutex<Inner>> }`); putting Drop on the wrapper means *every* clone
/// triggers teardown when it goes out of scope, which catastrophically
/// SIGTERMs the freshly-spawned tun2socks the moment `enable()` returns.
/// Putting it on `Inner` means cleanup runs exactly once — when the last
/// Arc reference is gone (typically app shutdown).
impl Drop for Inner {
    fn drop(&mut self) {
        // Touch the sigfile so the launcher loop (still running as root)
        // notices and SIGTERMs tun2socks. Best-effort.
        if let Some(sf) = &self.sigfile {
            let _ = std::fs::write(sf, b"stop");
        }
        // If we still own a Child handle (Linux/Windows direct path, or
        // macOS-osascript that hasn't exited yet), kill it.
        if let Some(child) = &mut self.launcher {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(p) = &self.pid_file {
            let _ = std::fs::remove_file(p);
        }
    }
}

// ---------------------------------------------------------------------------
// Spawn strategies — cfg-split so each OS gets the right elevation flow.
// ---------------------------------------------------------------------------

/// One of the supported launch modes. The macOS branch carries the side-
/// channels (pidfile, log) that the supervisor polls/tails after osascript
/// exits.
enum SpawnedLauncher {
    /// Unprivileged: `Child` is tun2socks itself. Used by the test bypass
    /// (`NEXRAY_TUN_NO_ELEVATION=1`) and as the fallback on platforms
    /// without an elevation strategy.
    Direct(Child),
    /// Elevated launcher: `Child` is the elevation wrapper (osascript on
    /// macOS, pkexec on Linux, `powershell Start-Process -Verb RunAs` on
    /// Windows), kept alive for the full session. The launcher script
    /// writes its actually-chosen iface name to `iface_file` (on macOS the
    /// hint may be busy so it iterates utun numbers; on Linux/Windows this
    /// just records the hint we passed in).
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    Privileged {
        child: Child,
        pidfile: PathBuf,
        log_path: PathBuf,
        iface_file: PathBuf,
    },
}

fn spawn_strategy(
    binary: &Path,
    iface: &str,
    socks_addr: &str,
    sigfile: &Path,
    bypass_ips: &[String],
) -> std::io::Result<SpawnedLauncher> {
    if std::env::var_os("NEXRAY_TUN_NO_ELEVATION").is_some() {
        return spawn_unprivileged(binary, iface, socks_addr).map(SpawnedLauncher::Direct);
    }

    #[cfg(target_os = "macos")]
    {
        spawn_via_osascript(binary, iface, socks_addr, sigfile, bypass_ips)
    }
    #[cfg(target_os = "linux")]
    {
        // pkexec missing → polkit isn't installed; fall back to direct.
        // tun2socks will then immediately surface the EPERM error to the
        // user with a "launch with sudo or grant the helper tool" hint.
        if !pkexec_available() {
            tracing::warn!(
                target: "tun",
                "pkexec not on PATH — falling back to unprivileged spawn (tun2socks will EPERM)",
            );
            return spawn_unprivileged(binary, iface, socks_addr).map(SpawnedLauncher::Direct);
        }
        spawn_via_pkexec(binary, iface, socks_addr, sigfile, bypass_ips)
    }
    #[cfg(target_os = "windows")]
    {
        spawn_via_runas(binary, iface, socks_addr, sigfile, bypass_ips)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = sigfile; // unused outside macOS / Linux / Windows
        let _ = bypass_ips;
        spawn_unprivileged(binary, iface, socks_addr).map(SpawnedLauncher::Direct)
    }
}

fn spawn_unprivileged(binary: &Path, iface: &str, socks_addr: &str) -> std::io::Result<Child> {
    let mut cmd = Command::new(binary);
    cmd.args([
        "-device",
        iface,
        "-proxy",
        &format!("socks5://{socks_addr}"),
        "-loglevel",
        "warn",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    cmd.spawn()
}

/// macOS-only: wrap tun2socks in `osascript do shell script ... with
/// administrator privileges`. The inner command is the launcher script,
/// run synchronously — osascript blocks for the full session. We keep the
/// osascript `Child` handle alive throughout, polling the launcher's
/// pidfile to learn the privileged tun2socks PID and tailing the log file
/// for live error surfacing. Teardown happens by `touch`ing the sigfile —
/// the launcher's poll loop notices, SIGTERMs tun2socks, exits, the script
/// exits, and osascript exits. One password prompt per session.
///
/// (Earlier iterations tried `& disown` to detach the launcher so
/// `do shell script` could return immediately. This was unreliable: the
/// detach interacted poorly with AppleScript's authorization context and
/// the launcher sometimes wasn't actually privileged. Synchronous-block
/// avoids that whole class of bug.)
#[cfg(target_os = "macos")]
fn spawn_via_osascript(
    binary: &Path,
    iface: &str,
    socks_addr: &str,
    sigfile: &Path,
    bypass_ips: &[String],
) -> std::io::Result<SpawnedLauncher> {
    let nonce = now_ms();
    let tmp = std::env::temp_dir();
    let script_path = tmp.join(format!("nexray-tun-launcher-{nonce}.sh"));
    let log_path = tmp.join(format!("nexray-tun-{nonce}.log"));
    let pidfile_path = tmp.join(format!("nexray-tun-{nonce}.pid"));
    let iface_file = tmp.join(format!("nexray-tun-{nonce}.iface"));
    let script = build_launcher_script_macos(LauncherPaths {
        log: &log_path,
        pidfile: &pidfile_path,
        sigfile,
        binary,
        iface,
        socks_addr,
        bypass_ips,
        iface_file: &iface_file,
        parent_pid: std::process::id(),
    });
    std::fs::write(&script_path, script)?;
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&script_path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script_path, perms)?;

    // AppleScript runs the launcher synchronously. Keep the osascript Child
    // alive — supervisor.disable() will touch the sigfile to bring it down.
    let inner_cmd = format!(
        "/bin/bash {script}",
        script = shell_single_quote(&script_path.to_string_lossy())
    );
    // `with prompt "..."` controls the message body of the macOS auth
    // dialog. The dialog *title* — currently "osascript" — is set by
    // macOS from the calling binary's bundle identity and we can only
    // change that with a code-signed privileged helper (SMJobBless) or
    // by wrapping the spawn in our own .app bundle with an Info.plist.
    // Both are out of scope for an unsigned dev build, but the prompt
    // line at least lets the user see "Nexray TUN" before they type
    // their password.
    let applescript = format!(
        "do shell script \"{cmd}\" with prompt \"Nexray TUN\" with administrator privileges",
        cmd = applescript_double_quote(&inner_cmd)
    );

    let mut cmd = Command::new("/usr/bin/osascript");
    cmd.args(["-e", &applescript])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn()?;
    Ok(SpawnedLauncher::Privileged {
        child,
        pidfile: pidfile_path,
        log_path,
        iface_file,
    })
}

/// Linux-only: wrap tun2socks in `pkexec /bin/bash <launcher>`. polkit
/// presents a graphical auth dialog (or TTY prompt under SSH); after the
/// user authenticates, pkexec setuid's to root and execs bash on the
/// launcher script. The pkexec process stays alive for the full session
/// (the script blocks until the sigfile is touched), so `disable()` can
/// SIGTERM it to tear everything down — the launcher's poll loop catches
/// the parent-died signal as a fallback. One auth prompt per session.
#[cfg(target_os = "linux")]
fn spawn_via_pkexec(
    binary: &Path,
    iface: &str,
    socks_addr: &str,
    sigfile: &Path,
    bypass_ips: &[String],
) -> std::io::Result<SpawnedLauncher> {
    let nonce = now_ms();
    let tmp = std::env::temp_dir();
    let script_path = tmp.join(format!("nexray-tun-launcher-{nonce}.sh"));
    let log_path = tmp.join(format!("nexray-tun-{nonce}.log"));
    let pidfile_path = tmp.join(format!("nexray-tun-{nonce}.pid"));
    let iface_file = tmp.join(format!("nexray-tun-{nonce}.iface"));
    let script = build_launcher_script_linux(LauncherPaths {
        log: &log_path,
        pidfile: &pidfile_path,
        sigfile,
        binary,
        iface,
        socks_addr,
        bypass_ips,
        iface_file: &iface_file,
        parent_pid: std::process::id(),
    });
    std::fs::write(&script_path, script)?;
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&script_path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script_path, perms)?;

    // `pkexec` exits with the child's status; signals (SIGTERM) are
    // propagated to the elevated process by pkexec's own signal handler.
    // We pass `--disable-internal-agent` so polkit's text agent doesn't
    // try to grab a TTY when the desktop's polkit-gnome / kdewallet /
    // mate-polkit agent is already running and would prompt graphically.
    let mut cmd = Command::new("pkexec");
    cmd.arg("--disable-internal-agent")
        .arg("/bin/bash")
        .arg(&script_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn()?;
    Ok(SpawnedLauncher::Privileged {
        child,
        pidfile: pidfile_path,
        log_path,
        iface_file,
    })
}

/// Manual `which pkexec`: walk PATH and stat each candidate. Avoids a
/// new dep just for this one check. Linux-only.
#[cfg(target_os = "linux")]
fn pkexec_available() -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path) {
        if dir.join("pkexec").is_file() {
            return true;
        }
    }
    false
}

/// Windows-only: wrap the launcher in `powershell -Command Start-Process
/// powershell -Verb RunAs -Wait`. The outer powershell waits on the
/// elevated child for the full session, so the supervisor's existing
/// `child.kill()` on disable() also tears down the elevated process via
/// the launcher's parent-pid watchdog. UAC consents once per session.
///
/// Quoting note: the inner argument list for `Start-Process -ArgumentList`
/// is a PowerShell array literal; each element is wrapped in single
/// quotes and any embedded single quote is doubled. We deliberately use
/// `'@(...)` over a single-string ArgumentList because PowerShell's
/// command-line splitter has subtle differences from Win32's
/// CommandLineToArgvW that break paths containing spaces.
#[cfg(target_os = "windows")]
fn spawn_via_runas(
    binary: &Path,
    iface: &str,
    socks_addr: &str,
    sigfile: &Path,
    bypass_ips: &[String],
) -> std::io::Result<SpawnedLauncher> {
    let nonce = now_ms();
    let tmp = std::env::temp_dir();
    let script_path = tmp.join(format!("nexray-tun-launcher-{nonce}.ps1"));
    let log_path = tmp.join(format!("nexray-tun-{nonce}.log"));
    let pidfile_path = tmp.join(format!("nexray-tun-{nonce}.pid"));
    let iface_file = tmp.join(format!("nexray-tun-{nonce}.iface"));
    let script = build_launcher_script_windows(LauncherPaths {
        log: &log_path,
        pidfile: &pidfile_path,
        sigfile,
        binary,
        iface,
        socks_addr,
        bypass_ips,
        iface_file: &iface_file,
        parent_pid: std::process::id(),
    });
    std::fs::write(&script_path, script)?;

    // PowerShell single-quoted strings only need ' → '' escaping; no
    // backslash dance. Build the inner Start-Process invocation as a
    // single command string passed via `-Command` to the outer
    // powershell.
    let q = ps_single_quote(&script_path.display().to_string());
    let outer_cmd = format!(
        "Start-Process -FilePath 'powershell.exe' \
         -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',{q}) \
         -Verb RunAs -Wait -WindowStyle Hidden"
    );

    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-Command",
        &outer_cmd,
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let child = cmd.spawn()?;
    Ok(SpawnedLauncher::Privileged {
        child,
        pidfile: pidfile_path,
        log_path,
        iface_file,
    })
}

/// PowerShell single-quote escape: doubled single quotes are the only
/// special character inside a single-quoted PowerShell literal.
#[cfg(target_os = "windows")]
fn ps_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push('\'');
            out.push('\'');
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Inputs to `build_launcher_script_*`. Bundled so the call site is self-
/// documenting and the test can construct one inline.
#[doc(hidden)]
pub struct LauncherPaths<'a> {
    pub log: &'a Path,
    pub pidfile: &'a Path,
    pub sigfile: &'a Path,
    pub binary: &'a Path,
    /// Hint at which utun number to start from. The launcher will iterate
    /// upward to find a free one if this is busy. Pass an arbitrary string
    /// like "nexray-tun" on Linux/Windows where iteration isn't applied.
    pub iface: &'a str,
    pub socks_addr: &'a str,
    /// IPv4 addresses (one per line acceptable) that must reach the network
    /// via the *original* default gateway rather than through the tunnel.
    /// Typically the proxy server's own IP — without this, xray's upstream
    /// connection to the VPS would loop back through tun2socks.
    pub bypass_ips: &'a [String],
    /// Path the launcher writes the actually-chosen iface name to (only
    /// meaningful on macOS where we iterate utun numbers). Supervisor
    /// reads this after the pidfile appears so `interface_name` reflects
    /// reality, not the hint we passed in.
    pub iface_file: &'a Path,
    /// PID of the nexray (host) process. The privileged launcher polls
    /// this each iteration with `kill -0`; when nexray dies (Ctrl+C,
    /// panic, SIGKILL — anything that bypasses our Drop), the launcher
    /// notices within ~300ms and tears itself down. Without this the
    /// kernel keeps the split-default routes installed and the user
    /// loses internet until manual cleanup.
    pub parent_pid: u32,
}

/// Generate the macOS bash launcher script that the privileged osascript
/// shell execs. Extracted so tests can run it directly (without osascript)
/// and verify the FSM contracts: writes pidfile, drains stderr to log,
/// removes pidfile on exit, honours the sigfile for cooperative shutdown,
/// and brings up routing so packets actually flow through the tunnel.
#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn build_launcher_script_macos(p: LauncherPaths<'_>) -> String {
    // Bypass IPs become a space-separated list embedded in the script.
    // We trust the supervisor to have validated these (they came out of
    // a DNS lookup of the active profile's address). Filter to safe chars
    // defensively anyway.
    let bypass_list = p
        .bypass_ips
        .iter()
        .filter(|ip| {
            ip.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':')
        })
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        "#!/bin/bash\n\
         set -u\n\
         LOG={log:?}\n\
         PIDFILE={pid:?}\n\
         SIGFILE={sig:?}\n\
         IFACE_FILE={iface_file:?}\n\
         BIN={bin:?}\n\
         IFACE_HINT={iface:?}\n\
         PROXY=\"socks5://{socks}\"\n\
         BYPASS_IPS=\"{bypass}\"\n\
         PARENT_PID={parent_pid}\n\
         TUN_IP=\"198.18.0.1\"\n\
         \n\
         : > \"$LOG\"\n\
         chmod 644 \"$LOG\"\n\
         \n\
         # Find a free utun device. macOS leaks utun allocations between\n\
         # sessions sometimes — the kernel reports \"resource busy\" on the\n\
         # exact device tun2socks tries to claim. Iterate from the hint up\n\
         # to +20 and pick the first that isn't already listed.\n\
         IFACE=\"$IFACE_HINT\"\n\
         if [[ \"$IFACE_HINT\" == utun* ]]; then\n\
           HINT_NUM=${{IFACE_HINT#utun}}\n\
           if [[ \"$HINT_NUM\" =~ ^[0-9]+$ ]]; then\n\
             for OFFSET in $(seq 0 20); do\n\
               CAND=\"utun$((HINT_NUM + OFFSET))\"\n\
               if ! /sbin/ifconfig \"$CAND\" >/dev/null 2>&1; then\n\
                 IFACE=\"$CAND\"\n\
                 break\n\
               fi\n\
             done\n\
           fi\n\
         fi\n\
         echo \"$IFACE\" > \"$IFACE_FILE\"\n\
         chmod 644 \"$IFACE_FILE\"\n\
         \n\
         # Diagnostic header so we can tell post-mortem what context the\n\
         # script ran in (uid, ppid, env, whether tun2socks even ran).\n\
         {{\n\
           echo \"--- nexray-tun launcher diag ---\"\n\
           echo \"date: $(date)\"\n\
           echo \"uid=$(id -u) gid=$(id -g) user=$(id -un)\"\n\
           echo \"pid=$$ ppid=$PPID\"\n\
           echo \"BIN=$BIN\"\n\
           echo \"IFACE_HINT=$IFACE_HINT IFACE_PICKED=$IFACE TUN_IP=$TUN_IP\"\n\
           echo \"BYPASS_IPS=$BYPASS_IPS\"\n\
         }} >> \"$LOG\" 2>&1\n\
         \n\
         # Look up the original default gateway/interface BEFORE we touch\n\
         # routes. We need both for /32 bypass routes (per-host via gw) and\n\
         # to restore on teardown. If empty, skip bypass setup; routing\n\
         # will still install but xray's upstream connection may loop.\n\
         LOCAL_GW=$(/sbin/route -n get default 2>/dev/null | awk '/gateway:/ {{print $2}}')\n\
         LOCAL_IF=$(/sbin/route -n get default 2>/dev/null | awk '/interface:/ {{print $2}}')\n\
         # IPv6 default — gateway may include a zone-id like %en0 which\n\
         # we must keep when adding /128 bypass routes.\n\
         LOCAL_GW6=$(/sbin/route -n get -inet6 default 2>/dev/null | awk '/gateway:/ {{print $2}}')\n\
         echo \"LOCAL_GW=$LOCAL_GW LOCAL_IF=$LOCAL_IF LOCAL_GW6=$LOCAL_GW6\" >> \"$LOG\"\n\
         echo \"--- tun2socks output below ---\" >> \"$LOG\"\n\
         \n\
         # Background tun2socks; stderr/stdout both → LOG.\n\
         \"$BIN\" -device \"$IFACE\" -proxy \"$PROXY\" -loglevel warn \\\n\
           >>\"$LOG\" 2>&1 &\n\
         TUN_PID=$!\n\
         echo \"$TUN_PID\" > \"$PIDFILE\"\n\
         chmod 644 \"$PIDFILE\"\n\
         echo \"tun2socks spawned with pid=$TUN_PID\" >> \"$LOG\"\n\
         \n\
         # Give tun2socks ~500ms to actually create the utun device.\n\
         sleep 0.5\n\
         \n\
         # Configure utun's IPv4 address (point-to-point, /32).\n\
         /sbin/ifconfig \"$IFACE\" \"$TUN_IP\" \"$TUN_IP\" up >> \"$LOG\" 2>&1 \\\n\
           && echo \"ifconfig $IFACE up at $TUN_IP\" >> \"$LOG\"\n\
         # And an IPv6 ULA so IPv6 traffic can also be routed at it.\n\
         /sbin/ifconfig \"$IFACE\" inet6 fc00::1 prefixlen 128 add >> \"$LOG\" 2>&1 \\\n\
           && echo \"ifconfig $IFACE inet6 fc00::1/128 added\" >> \"$LOG\"\n\
         \n\
         # Bypass routes: each proxy IP must reach the internet via the\n\
         # ORIGINAL default gateway, otherwise xray's upstream connection\n\
         # to it would route back into the tunnel and loop forever. Split\n\
         # by address family — IPv6 needs a different `route` invocation.\n\
         for IP in $BYPASS_IPS; do\n\
           if [[ \"$IP\" == *:* ]]; then\n\
             # IPv6 bypass\n\
             if [ -n \"$LOCAL_GW6\" ]; then\n\
               /sbin/route -n add -inet6 -host \"$IP\" \"$LOCAL_GW6\" >> \"$LOG\" 2>&1 \\\n\
                 && echo \"bypass v6: $IP -> $LOCAL_GW6\" >> \"$LOG\"\n\
             fi\n\
           else\n\
             # IPv4 bypass\n\
             if [ -n \"$LOCAL_GW\" ]; then\n\
               /sbin/route -n add -host \"$IP\" \"$LOCAL_GW\" >> \"$LOG\" 2>&1 \\\n\
                 && echo \"bypass v4: $IP -> $LOCAL_GW\" >> \"$LOG\"\n\
             fi\n\
           fi\n\
         done\n\
         \n\
         # Split-default trick: covers all of 0.0.0.0/0 (and ::/0) with\n\
         # /1 + /1 routes that beat the existing default by specificity.\n\
         # Easy clean rollback (vs `route change default`).\n\
         /sbin/route -n add -net 0.0.0.0/1 -interface \"$IFACE\" >> \"$LOG\" 2>&1\n\
         /sbin/route -n add -net 128.0.0.0/1 -interface \"$IFACE\" >> \"$LOG\" 2>&1\n\
         /sbin/route -n add -inet6 -net ::/1 -interface \"$IFACE\" >> \"$LOG\" 2>&1\n\
         /sbin/route -n add -inet6 -net 8000::/1 -interface \"$IFACE\" >> \"$LOG\" 2>&1\n\
         echo \"split-default routes (v4+v6) installed via $IFACE\" >> \"$LOG\"\n\
         \n\
         # Cooperative shutdown loop. Polls every 0.3s for either:\n\
         #   1. sigfile present → user clicked Stop TUN cleanly\n\
         #   2. parent (nexray) PID dead → app force-quit / Ctrl+C / crashed\n\
         # Either way: SIGTERM tun2socks, fall through to the teardown\n\
         # block below so routes/utun get cleaned up regardless of how the\n\
         # session ended.\n\
         REASON=\"\"\n\
         while kill -0 \"$TUN_PID\" 2>/dev/null; do\n\
           if [ -e \"$SIGFILE\" ]; then\n\
             rm -f \"$SIGFILE\"\n\
             REASON=\"sigfile\"\n\
             break\n\
           fi\n\
           if ! kill -0 \"$PARENT_PID\" 2>/dev/null; then\n\
             REASON=\"parent_died\"\n\
             break\n\
           fi\n\
           sleep 0.3\n\
         done\n\
         echo \"shutdown trigger: ${{REASON:-tun2socks_exited}}\" >> \"$LOG\"\n\
         if [ -n \"$REASON\" ]; then\n\
           kill -TERM \"$TUN_PID\" 2>/dev/null || true\n\
           sleep 1\n\
           kill -KILL \"$TUN_PID\" 2>/dev/null || true\n\
         fi\n\
         \n\
         wait \"$TUN_PID\" 2>/dev/null\n\
         echo \"tun2socks exited with status $?\" >> \"$LOG\"\n\
         \n\
         # Tear down routes and addresses. We added these; we own removing\n\
         # them. Errors swallowed because some entries may have failed to\n\
         # install or already been removed.\n\
         /sbin/route -n delete -net 0.0.0.0/1 -interface \"$IFACE\" >> \"$LOG\" 2>&1 || true\n\
         /sbin/route -n delete -net 128.0.0.0/1 -interface \"$IFACE\" >> \"$LOG\" 2>&1 || true\n\
         /sbin/route -n delete -inet6 -net ::/1 -interface \"$IFACE\" >> \"$LOG\" 2>&1 || true\n\
         /sbin/route -n delete -inet6 -net 8000::/1 -interface \"$IFACE\" >> \"$LOG\" 2>&1 || true\n\
         for IP in $BYPASS_IPS; do\n\
           if [[ \"$IP\" == *:* ]]; then\n\
             [ -n \"$LOCAL_GW6\" ] && /sbin/route -n delete -inet6 -host \"$IP\" \"$LOCAL_GW6\" >> \"$LOG\" 2>&1 || true\n\
           else\n\
             [ -n \"$LOCAL_GW\" ] && /sbin/route -n delete -host \"$IP\" \"$LOCAL_GW\" >> \"$LOG\" 2>&1 || true\n\
           fi\n\
         done\n\
         /sbin/ifconfig \"$IFACE\" down >> \"$LOG\" 2>&1 || true\n\
         echo \"routing torn down\" >> \"$LOG\"\n\
         \n\
         rm -f \"$PIDFILE\"\n\
         rm -f \"$IFACE_FILE\"\n\
         exit 0\n",
        log = p.log,
        pid = p.pidfile,
        sig = p.sigfile,
        iface_file = p.iface_file,
        bin = p.binary,
        iface = p.iface,
        socks = p.socks_addr,
        bypass = bypass_list,
        parent_pid = p.parent_pid,
    )
}

/// Linux equivalent of `build_launcher_script_macos`. Same FSM —
/// pidfile + sigfile + parent-pid watch + cooperative teardown — but
/// uses iproute2 (`ip link`, `ip addr`, `ip route`) instead of macOS
/// `ifconfig`/`route`. tun2socks creates the device once it's running
/// as root; we then bring it up, assign IPs, install split-default
/// routes that beat the existing default by specificity, and add per-
/// host bypass routes so xray's upstream connection escapes the tunnel.
#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn build_launcher_script_linux(p: LauncherPaths<'_>) -> String {
    let bypass_list = p
        .bypass_ips
        .iter()
        .filter(|ip| {
            ip.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':')
        })
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        "#!/bin/bash\n\
         set -u\n\
         LOG={log:?}\n\
         PIDFILE={pid:?}\n\
         SIGFILE={sig:?}\n\
         IFACE_FILE={iface_file:?}\n\
         BIN={bin:?}\n\
         IFACE_HINT={iface:?}\n\
         PROXY=\"socks5://{socks}\"\n\
         BYPASS_IPS=\"{bypass}\"\n\
         PARENT_PID={parent_pid}\n\
         TUN_IP=\"198.18.0.1\"\n\
         \n\
         : > \"$LOG\"\n\
         chmod 644 \"$LOG\"\n\
         \n\
         # Linux iface naming is unconstrained — keep the hint as-is.\n\
         IFACE=\"$IFACE_HINT\"\n\
         echo \"$IFACE\" > \"$IFACE_FILE\"\n\
         chmod 644 \"$IFACE_FILE\"\n\
         \n\
         {{\n\
           echo \"--- nexray-tun launcher diag (linux) ---\"\n\
           echo \"date: $(date)\"\n\
           echo \"uid=$(id -u) gid=$(id -g) user=$(id -un)\"\n\
           echo \"pid=$$ ppid=$PPID\"\n\
           echo \"BIN=$BIN\"\n\
           echo \"IFACE_HINT=$IFACE_HINT IFACE_PICKED=$IFACE TUN_IP=$TUN_IP\"\n\
           echo \"BYPASS_IPS=$BYPASS_IPS\"\n\
         }} >> \"$LOG\" 2>&1\n\
         \n\
         # Discover the original default gateway+iface BEFORE we touch\n\
         # routing, so bypass routes can escape the tunnel and we can\n\
         # restore the prior state on teardown.\n\
         DEF_LINE=$(ip -4 route show default 2>/dev/null | head -1)\n\
         LOCAL_GW=$(echo \"$DEF_LINE\" | awk '{{print $3}}')\n\
         LOCAL_IF=$(echo \"$DEF_LINE\" | awk '{{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}}')\n\
         DEF_LINE6=$(ip -6 route show default 2>/dev/null | head -1)\n\
         LOCAL_GW6=$(echo \"$DEF_LINE6\" | awk '{{print $3}}')\n\
         LOCAL_IF6=$(echo \"$DEF_LINE6\" | awk '{{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}}')\n\
         echo \"LOCAL_GW=$LOCAL_GW LOCAL_IF=$LOCAL_IF LOCAL_GW6=$LOCAL_GW6 LOCAL_IF6=$LOCAL_IF6\" >> \"$LOG\"\n\
         echo \"--- tun2socks output below ---\" >> \"$LOG\"\n\
         \n\
         # Background tun2socks; stderr/stdout both → LOG.\n\
         \"$BIN\" -device \"$IFACE\" -proxy \"$PROXY\" -loglevel warn \\\n\
           >>\"$LOG\" 2>&1 &\n\
         TUN_PID=$!\n\
         echo \"$TUN_PID\" > \"$PIDFILE\"\n\
         chmod 644 \"$PIDFILE\"\n\
         echo \"tun2socks spawned with pid=$TUN_PID\" >> \"$LOG\"\n\
         \n\
         # Give tun2socks ~500ms to ioctl(TUNSETIFF) and create the device.\n\
         sleep 0.5\n\
         \n\
         # Bring the device up and assign IPv4 + IPv6 ULA addresses.\n\
         ip link set \"$IFACE\" mtu 1500 up >> \"$LOG\" 2>&1 \\\n\
           && echo \"ip link set $IFACE up\" >> \"$LOG\"\n\
         ip addr add \"$TUN_IP/30\" dev \"$IFACE\" >> \"$LOG\" 2>&1 \\\n\
           && echo \"ip addr add $TUN_IP/30 dev $IFACE\" >> \"$LOG\"\n\
         ip -6 addr add \"fc00::1/128\" dev \"$IFACE\" >> \"$LOG\" 2>&1 \\\n\
           && echo \"ip -6 addr add fc00::1/128 dev $IFACE\" >> \"$LOG\"\n\
         \n\
         # Bypass routes: each proxy-server IP must reach the network via\n\
         # the ORIGINAL default gateway, otherwise xray's upstream\n\
         # connection would loop back into the tunnel forever.\n\
         for IP in $BYPASS_IPS; do\n\
           if [[ \"$IP\" == *:* ]]; then\n\
             if [ -n \"$LOCAL_GW6\" ] && [ -n \"$LOCAL_IF6\" ]; then\n\
               ip -6 route add \"$IP\" via \"$LOCAL_GW6\" dev \"$LOCAL_IF6\" >> \"$LOG\" 2>&1 \\\n\
                 && echo \"bypass v6: $IP -> $LOCAL_GW6 dev $LOCAL_IF6\" >> \"$LOG\"\n\
             fi\n\
           else\n\
             if [ -n \"$LOCAL_GW\" ] && [ -n \"$LOCAL_IF\" ]; then\n\
               ip route add \"$IP\" via \"$LOCAL_GW\" dev \"$LOCAL_IF\" >> \"$LOG\" 2>&1 \\\n\
                 && echo \"bypass v4: $IP -> $LOCAL_GW dev $LOCAL_IF\" >> \"$LOG\"\n\
             fi\n\
           fi\n\
         done\n\
         \n\
         # Split-default trick (matches the macOS path): /1 + /1 routes\n\
         # cover all of 0/0 and ::/0 with higher specificity than the\n\
         # existing default, so they win without us touching the original\n\
         # default route entry. Easy clean rollback at teardown.\n\
         ip route add 0.0.0.0/1 dev \"$IFACE\" >> \"$LOG\" 2>&1\n\
         ip route add 128.0.0.0/1 dev \"$IFACE\" >> \"$LOG\" 2>&1\n\
         ip -6 route add ::/1 dev \"$IFACE\" >> \"$LOG\" 2>&1\n\
         ip -6 route add 8000::/1 dev \"$IFACE\" >> \"$LOG\" 2>&1\n\
         echo \"split-default routes (v4+v6) installed via $IFACE\" >> \"$LOG\"\n\
         \n\
         # Cooperative shutdown loop. Polls every 0.3s for either:\n\
         #   1. sigfile present → user clicked Stop TUN cleanly\n\
         #   2. parent (nexray) PID dead → app force-quit / Ctrl+C / crashed\n\
         REASON=\"\"\n\
         while kill -0 \"$TUN_PID\" 2>/dev/null; do\n\
           if [ -e \"$SIGFILE\" ]; then\n\
             rm -f \"$SIGFILE\"\n\
             REASON=\"sigfile\"\n\
             break\n\
           fi\n\
           if ! kill -0 \"$PARENT_PID\" 2>/dev/null; then\n\
             REASON=\"parent_died\"\n\
             break\n\
           fi\n\
           sleep 0.3\n\
         done\n\
         echo \"shutdown trigger: ${{REASON:-tun2socks_exited}}\" >> \"$LOG\"\n\
         if [ -n \"$REASON\" ]; then\n\
           kill -TERM \"$TUN_PID\" 2>/dev/null || true\n\
           sleep 1\n\
           kill -KILL \"$TUN_PID\" 2>/dev/null || true\n\
         fi\n\
         \n\
         wait \"$TUN_PID\" 2>/dev/null\n\
         echo \"tun2socks exited with status $?\" >> \"$LOG\"\n\
         \n\
         # Tear down routes and addresses we installed. Errors are\n\
         # swallowed because some entries may already be gone (e.g.\n\
         # tun2socks deletes the device on exit).\n\
         ip route del 0.0.0.0/1 dev \"$IFACE\" >> \"$LOG\" 2>&1 || true\n\
         ip route del 128.0.0.0/1 dev \"$IFACE\" >> \"$LOG\" 2>&1 || true\n\
         ip -6 route del ::/1 dev \"$IFACE\" >> \"$LOG\" 2>&1 || true\n\
         ip -6 route del 8000::/1 dev \"$IFACE\" >> \"$LOG\" 2>&1 || true\n\
         for IP in $BYPASS_IPS; do\n\
           if [[ \"$IP\" == *:* ]]; then\n\
             [ -n \"$LOCAL_GW6\" ] && ip -6 route del \"$IP\" via \"$LOCAL_GW6\" >> \"$LOG\" 2>&1 || true\n\
           else\n\
             [ -n \"$LOCAL_GW\" ] && ip route del \"$IP\" via \"$LOCAL_GW\" >> \"$LOG\" 2>&1 || true\n\
           fi\n\
         done\n\
         ip link set \"$IFACE\" down >> \"$LOG\" 2>&1 || true\n\
         echo \"routing torn down\" >> \"$LOG\"\n\
         \n\
         rm -f \"$PIDFILE\"\n\
         rm -f \"$IFACE_FILE\"\n\
         exit 0\n",
        log = p.log,
        pid = p.pidfile,
        sig = p.sigfile,
        iface_file = p.iface_file,
        bin = p.binary,
        iface = p.iface,
        socks = p.socks_addr,
        bypass = bypass_list,
        parent_pid = p.parent_pid,
    )
}

/// Windows equivalent of `build_launcher_script_macos` /
/// `build_launcher_script_linux`. Same FSM — pidfile + sigfile +
/// parent-pid watch + cooperative teardown — but emitted as a PowerShell
/// `.ps1`. Uses `Get-NetRoute` / `New-NetIPAddress` / `New-NetRoute` to
/// install split-default routing on the Wintun adapter that tun2socks
/// creates, plus per-host bypass routes so xray's upstream connection
/// escapes the tunnel. Errors are swallowed via
/// `-ErrorAction SilentlyContinue` because some entries may already be
/// gone by teardown time (the device disappears with tun2socks).
#[doc(hidden)]
#[cfg(target_os = "windows")]
pub fn build_launcher_script_windows(p: LauncherPaths<'_>) -> String {
    // Same defensive whitelist as the macOS/Linux path. `:` for IPv6,
    // `.` for IPv4. PowerShell will split the resulting space-separated
    // string back into an array.
    let bypass_list = p
        .bypass_ips
        .iter()
        .filter(|ip| {
            ip.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':')
        })
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");

    // PowerShell paths get embedded as single-quoted literals; double
    // any embedded single quotes per PS rules.
    let q = |path: &Path| -> String { ps_single_quote_static(&path.display().to_string()) };

    format!(
        "$ErrorActionPreference = 'Continue'\n\
         $LOG = {log}\n\
         $PIDFILE = {pid}\n\
         $SIGFILE = {sig}\n\
         $IFACE_FILE = {iface_file}\n\
         $BIN = {bin}\n\
         $IFACE_HINT = '{iface}'\n\
         $PROXY = 'socks5://{socks}'\n\
         $BYPASS_IPS_RAW = '{bypass}'\n\
         $PARENT_PID = {parent_pid}\n\
         $TUN_IP = '198.18.0.1'\n\
         \n\
         '' | Out-File -FilePath $LOG -Encoding ASCII\n\
         \n\
         # Wintun adapter naming is unconstrained — use the hint as-is.\n\
         $IFACE = $IFACE_HINT\n\
         $IFACE | Out-File -FilePath $IFACE_FILE -Encoding ASCII\n\
         \n\
         '--- nexray-tun launcher diag (windows) ---' | Add-Content $LOG\n\
         \"date: $(Get-Date)\" | Add-Content $LOG\n\
         \"user: $(whoami)\" | Add-Content $LOG\n\
         \"pid: $PID  parent: $PARENT_PID\" | Add-Content $LOG\n\
         \"BIN: $BIN\" | Add-Content $LOG\n\
         \"IFACE: $IFACE  TUN_IP: $TUN_IP\" | Add-Content $LOG\n\
         \"BYPASS_IPS: $BYPASS_IPS_RAW\" | Add-Content $LOG\n\
         \n\
         # Snapshot the original default gateway+iface BEFORE we touch\n\
         # routing, so bypass routes can escape the tunnel and we can\n\
         # restore prior state on teardown.\n\
         $DefRoute4 = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | \
             Sort-Object -Property RouteMetric | Select-Object -First 1\n\
         $LOCAL_GW  = if ($DefRoute4) {{ $DefRoute4.NextHop }} else {{ '' }}\n\
         $LOCAL_IDX = if ($DefRoute4) {{ $DefRoute4.ifIndex }} else {{ $null }}\n\
         $DefRoute6 = Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | \
             Sort-Object -Property RouteMetric | Select-Object -First 1\n\
         $LOCAL_GW6  = if ($DefRoute6) {{ $DefRoute6.NextHop }} else {{ '' }}\n\
         $LOCAL_IDX6 = if ($DefRoute6) {{ $DefRoute6.ifIndex }} else {{ $null }}\n\
         \"LOCAL_GW=$LOCAL_GW IDX=$LOCAL_IDX  LOCAL_GW6=$LOCAL_GW6 IDX6=$LOCAL_IDX6\" | Add-Content $LOG\n\
         '--- tun2socks output below ---' | Add-Content $LOG\n\
         \n\
         # Spawn tun2socks. Start-Process -PassThru returns the child\n\
         # process so we can capture its PID and wait on it later.\n\
         $proc = Start-Process -FilePath $BIN \\\n\
           -ArgumentList @('-device', $IFACE, '-proxy', $PROXY, '-loglevel', 'warn') \\\n\
           -RedirectStandardOutput $LOG -RedirectStandardError $LOG \\\n\
           -WindowStyle Hidden -PassThru\n\
         $TUN_PID = $proc.Id\n\
         \"$TUN_PID\" | Out-File -FilePath $PIDFILE -Encoding ASCII\n\
         \"tun2socks spawned with pid=$TUN_PID\" | Add-Content $LOG\n\
         \n\
         # Wait for Wintun to instantiate the adapter under the chosen\n\
         # name. Iterate so we don't race tun2socks on slow systems.\n\
         $Adapter = $null\n\
         for ($i = 0; $i -lt 25; $i++) {{\n\
           $Adapter = Get-NetAdapter -Name $IFACE -ErrorAction SilentlyContinue\n\
           if ($Adapter) {{ break }}\n\
           Start-Sleep -Milliseconds 200\n\
         }}\n\
         \n\
         if ($Adapter) {{\n\
           $TUN_IDX = $Adapter.ifIndex\n\
           \"adapter index: $TUN_IDX\" | Add-Content $LOG\n\
           \n\
           # Bring up + assign IPv4 + IPv6 ULA addresses.\n\
           Set-NetIPInterface -InterfaceIndex $TUN_IDX -InterfaceMetric 1 -ErrorAction SilentlyContinue\n\
           New-NetIPAddress -InterfaceIndex $TUN_IDX -IPAddress $TUN_IP -PrefixLength 30 \\\n\
             -ErrorAction SilentlyContinue | Out-Null\n\
           \"New-NetIPAddress $TUN_IP/30 idx=$TUN_IDX\" | Add-Content $LOG\n\
           \n\
           # Bypass routes: each proxy-server IP must reach the network\n\
           # via the ORIGINAL default gateway, otherwise xray's upstream\n\
           # connection would loop back into the tunnel forever.\n\
           foreach ($IP in ($BYPASS_IPS_RAW -split ' ')) {{\n\
             if ($IP -eq '') {{ continue }}\n\
             if ($IP -match ':') {{\n\
               if ($LOCAL_IDX6 -and $LOCAL_GW6) {{\n\
                 New-NetRoute -DestinationPrefix \"$IP/128\" -InterfaceIndex $LOCAL_IDX6 \\\n\
                   -NextHop $LOCAL_GW6 -ErrorAction SilentlyContinue | Out-Null\n\
                 \"bypass v6: $IP -> $LOCAL_GW6 (idx $LOCAL_IDX6)\" | Add-Content $LOG\n\
               }}\n\
             }} else {{\n\
               if ($LOCAL_IDX -and $LOCAL_GW) {{\n\
                 New-NetRoute -DestinationPrefix \"$IP/32\" -InterfaceIndex $LOCAL_IDX \\\n\
                   -NextHop $LOCAL_GW -ErrorAction SilentlyContinue | Out-Null\n\
                 \"bypass v4: $IP -> $LOCAL_GW (idx $LOCAL_IDX)\" | Add-Content $LOG\n\
               }}\n\
             }}\n\
           }}\n\
           \n\
           # Split-default trick: 0/1 + 128/1 beat the existing default\n\
           # by specificity. NextHop is unset → routes are interface-scoped.\n\
           New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceIndex $TUN_IDX \\\n\
             -NextHop $TUN_IP -ErrorAction SilentlyContinue | Out-Null\n\
           New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceIndex $TUN_IDX \\\n\
             -NextHop $TUN_IP -ErrorAction SilentlyContinue | Out-Null\n\
           New-NetRoute -DestinationPrefix '::/1' -InterfaceIndex $TUN_IDX \\\n\
             -ErrorAction SilentlyContinue | Out-Null\n\
           New-NetRoute -DestinationPrefix '8000::/1' -InterfaceIndex $TUN_IDX \\\n\
             -ErrorAction SilentlyContinue | Out-Null\n\
           \"split-default routes installed via $IFACE (idx $TUN_IDX)\" | Add-Content $LOG\n\
         }} else {{\n\
           'WARN: Wintun adapter never appeared; skipping route setup' | Add-Content $LOG\n\
         }}\n\
         \n\
         # Cooperative shutdown loop. Polls every 0.3s for either:\n\
         #   1. sigfile present → user clicked Stop TUN cleanly\n\
         #   2. parent (nexray) PID dead → app force-quit / Ctrl+C / crashed\n\
         #   3. tun2socks itself exited\n\
         $REASON = ''\n\
         while ($true) {{\n\
           if (-not (Get-Process -Id $TUN_PID -ErrorAction SilentlyContinue)) {{\n\
             $REASON = 'tun2socks_exited'; break\n\
           }}\n\
           if (Test-Path $SIGFILE) {{\n\
             Remove-Item -Force $SIGFILE -ErrorAction SilentlyContinue\n\
             $REASON = 'sigfile'; break\n\
           }}\n\
           if (-not (Get-Process -Id $PARENT_PID -ErrorAction SilentlyContinue)) {{\n\
             $REASON = 'parent_died'; break\n\
           }}\n\
           Start-Sleep -Milliseconds 300\n\
         }}\n\
         \"shutdown trigger: $REASON\" | Add-Content $LOG\n\
         \n\
         if ($REASON -eq 'sigfile' -or $REASON -eq 'parent_died') {{\n\
           Stop-Process -Id $TUN_PID -Force -ErrorAction SilentlyContinue\n\
           Start-Sleep -Seconds 1\n\
         }}\n\
         Wait-Process -Id $TUN_PID -ErrorAction SilentlyContinue\n\
         'tun2socks exited' | Add-Content $LOG\n\
         \n\
         # Tear down everything we installed. Errors swallowed because\n\
         # the Wintun adapter typically vanishes with tun2socks, taking\n\
         # its routes with it.\n\
         if ($Adapter) {{\n\
           Remove-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceIndex $TUN_IDX \\\n\
             -Confirm:$false -ErrorAction SilentlyContinue\n\
           Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceIndex $TUN_IDX \\\n\
             -Confirm:$false -ErrorAction SilentlyContinue\n\
           Remove-NetRoute -DestinationPrefix '::/1' -InterfaceIndex $TUN_IDX \\\n\
             -Confirm:$false -ErrorAction SilentlyContinue\n\
           Remove-NetRoute -DestinationPrefix '8000::/1' -InterfaceIndex $TUN_IDX \\\n\
             -Confirm:$false -ErrorAction SilentlyContinue\n\
         }}\n\
         foreach ($IP in ($BYPASS_IPS_RAW -split ' ')) {{\n\
           if ($IP -eq '') {{ continue }}\n\
           if ($IP -match ':') {{\n\
             Remove-NetRoute -DestinationPrefix \"$IP/128\" -Confirm:$false -ErrorAction SilentlyContinue\n\
           }} else {{\n\
             Remove-NetRoute -DestinationPrefix \"$IP/32\" -Confirm:$false -ErrorAction SilentlyContinue\n\
           }}\n\
         }}\n\
         'routing torn down' | Add-Content $LOG\n\
         \n\
         Remove-Item -Force $PIDFILE -ErrorAction SilentlyContinue\n\
         Remove-Item -Force $IFACE_FILE -ErrorAction SilentlyContinue\n\
         exit 0\n",
        log = q(p.log),
        pid = q(p.pidfile),
        sig = q(p.sigfile),
        iface_file = q(p.iface_file),
        bin = q(p.binary),
        iface = p.iface,
        socks = p.socks_addr,
        bypass = bypass_list,
        parent_pid = p.parent_pid,
    )
}

/// Free-function variant of `ps_single_quote` that's available on every
/// platform (so `build_launcher_script_windows` can be tested cross-OS
/// without the cfg gate around `ps_single_quote` excluding it). The two
/// functions intentionally have the same body.
#[cfg(target_os = "windows")]
fn ps_single_quote_static(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push('\'');
            out.push('\'');
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Tail the per-session log file, feeding lines through the same sticky-
/// error pipeline as `drain_lines`. Stops when the pidfile vanishes (the
/// launcher's exit signal) or when EOF + 1s passes with no new data.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn tail_log(log_path: &Path, pidfile_path: &Path, inner_arc: Arc<Mutex<Inner>>) {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Seek};
    let Ok(file) = File::open(log_path) else {
        return;
    };
    let mut reader = BufReader::new(file);
    let mut buf = String::new();
    loop {
        buf.clear();
        match reader.read_line(&mut buf) {
            Ok(0) => {
                // EOF. If pidfile is gone, the launcher exited — we're done.
                if !pidfile_path.exists() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
                // BufReader caches EOF state; re-seek to current pos to
                // pick up new data on next read.
                let pos = reader.stream_position().unwrap_or(0);
                let _ = reader.seek(std::io::SeekFrom::Start(pos));
            }
            Ok(_) => {
                let line = buf.trim_end_matches('\n').to_string();
                if line.is_empty() {
                    continue;
                }
                tracing::info!(target: "tun2socks", "{line}");
                let mut inner = lock(&inner_arc);
                let lower = line.to_ascii_lowercase();
                let is_error = lower.contains("fatal") || lower.contains("error");
                if is_error && inner.last_error.is_none() {
                    let msg = if lower.contains("operation not permitted")
                        && lower.contains("create tun")
                    {
                        format!(
                            "{line} — TUN device creation failed even with admin; \
                             another process may already own this utun."
                        )
                    } else {
                        line
                    };
                    inner.last_error = Some(msg);
                }
            }
            Err(_) => return,
        }
    }
}

/// Escape a string for embedding inside an AppleScript double-quoted string
/// literal. Backslashes and double quotes are the only characters AppleScript
/// itself treats specially.
#[cfg(target_os = "macos")]
fn applescript_double_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out
}

#[cfg(target_os = "macos")]
fn shell_single_quote(s: &str) -> String {
    // Escape any single quotes in the path by closing-and-reopening:
    //   foo'bar  →  'foo'\''bar'
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn make_sigfile_path() -> PathBuf {
    let nonce = now_ms();
    std::env::temp_dir().join(format!("nexray-tun-stop-{nonce}.sig"))
}

/// Drain the directly-spawned tun2socks's stderr line-by-line. Used on
/// Linux/Windows and the test bypass; the macOS-elevated path tails a
/// log file in `tail_log` instead.
fn drain_lines<R: std::io::Read + Send + 'static>(
    stream: R,
    inner_arc: Arc<Mutex<Inner>>,
    _: bool,
) {
    use std::io::{BufRead, BufReader};
    let reader = BufReader::new(stream);
    for line in reader.lines().map_while(Result::ok) {
        if line.trim().is_empty() {
            continue;
        }
        tracing::info!(target: "tun2socks", "{line}");
        let mut inner = lock(&inner_arc);
        let lower = line.to_ascii_lowercase();
        let is_error = lower.contains("fatal") || lower.contains("error");
        if is_error && inner.last_error.is_none() {
            let msg = if lower.contains("operation not permitted") && lower.contains("create tun") {
                format!(
                    "{line} — TUN device creation requires admin/root; \
                     launch with sudo or grant the helper tool \
                     (Phase-7 work)"
                )
            } else {
                line
            };
            inner.last_error = Some(msg);
        }
        if matches!(inner.state, TunState::Starting) {
            inner.state = TunState::Active;
        }
    }
}

fn snapshot(inner: &Inner) -> TunStatus {
    TunStatus {
        state: inner.state,
        interface_name: inner.interface_name.clone(),
        since_ms: inner.since_ms,
        last_error: inner.last_error.clone(),
    }
}

#[allow(clippy::expect_used)]
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().expect("tun supervisor mutex poisoned")
}

#[allow(clippy::expect_used)]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock pre-1970?")
        .as_millis() as u64
}
