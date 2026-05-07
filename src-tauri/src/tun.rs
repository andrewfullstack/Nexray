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
//! - **Linux** — TODO Phase 6.x: wrap with `pkexec` for the polkit prompt,
//!   falling back to a clear error when polkit is absent.
//! - **Windows** — TODO Phase 6.x: wrap with `ShellExecuteEx` `runas` verb
//!   for the UAC prompt, or use the `windows::Win32::UI::Shell` APIs.
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
            #[cfg(target_os = "macos")]
            SpawnedLauncher::Osascript {
                mut child,
                pidfile,
                log_path,
            } => {
                // macOS path. osascript stays alive for the whole session;
                // it presents the password prompt, runs the launcher script
                // as root, and only exits when the launcher exits (which
                // happens via sigfile teardown). We poll the pidfile to
                // learn when tun2socks is up.
                //
                // Race window: osascript may fail (user cancelled) before
                // the pidfile appears. So we interleave try_wait() with
                // pidfile polling, with a generous timeout to account for
                // the human typing their password.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                let pid_result = loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            // osascript already exited — pidfile may or
                            // may not exist. If it does, we caught it after
                            // a fast tun2socks crash; surface the log.
                            break Err(format!(
                                "osascript exited before pidfile appeared: {status}"
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
                        break Err(
                            "timed out waiting for launcher pidfile (60s) — admin \
                             prompt not answered or launcher script never ran"
                                .into(),
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(150));
                };

                let pid = match pid_result {
                    Ok(pid) => pid,
                    Err(why) => {
                        // Best-effort: kill osascript so it doesn't hang
                        // around if the prompt was still up.
                        let _ = child.kill();
                        let _ = child.wait();
                        // Surface the launcher log if it exists — that's
                        // where tun2socks's FATAL lines went.
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
                        let msg = format!("{why}; launcher log tail: {log_excerpt}");
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

                inner.state = TunState::Active;
                inner.launcher = Some(child);
                inner.privileged_pid = Some(pid);
                inner.sigfile = Some(sigfile);
                inner.privileged_pidfile = Some(pidfile);
                inner.log_path = Some(log_path);
                inner.interface_name = Some(iface_owned);
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
    /// Unprivileged or non-macOS: `Child` is tun2socks itself.
    Direct(Child),
    /// macOS-with-elevation: `Child` is osascript (which will exit shortly
    /// after auth completes; the launcher script then runs detached as
    /// root).
    #[cfg(target_os = "macos")]
    Osascript {
        child: Child,
        pidfile: PathBuf,
        log_path: PathBuf,
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
    #[cfg(not(target_os = "macos"))]
    {
        let _ = sigfile; // unused outside macOS
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
    let script = build_launcher_script(LauncherPaths {
        log: &log_path,
        pidfile: &pidfile_path,
        sigfile,
        binary,
        iface,
        socks_addr,
        bypass_ips,
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
    let applescript = format!(
        "do shell script \"{cmd}\" with administrator privileges",
        cmd = applescript_double_quote(&inner_cmd)
    );

    let mut cmd = Command::new("/usr/bin/osascript");
    cmd.args(["-e", &applescript])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn()?;
    Ok(SpawnedLauncher::Osascript {
        child,
        pidfile: pidfile_path,
        log_path,
    })
}

/// Inputs to `build_launcher_script`. Bundled so the call site is self-
/// documenting and the test can construct one inline.
#[doc(hidden)]
pub struct LauncherPaths<'a> {
    pub log: &'a Path,
    pub pidfile: &'a Path,
    pub sigfile: &'a Path,
    pub binary: &'a Path,
    pub iface: &'a str,
    pub socks_addr: &'a str,
    /// IPv4 addresses (one per line acceptable) that must reach the network
    /// via the *original* default gateway rather than through the tunnel.
    /// Typically the proxy server's own IP — without this, xray's upstream
    /// connection to the VPS would loop back through tun2socks.
    pub bypass_ips: &'a [String],
}

/// Generate the bash launcher script that the privileged osascript shell
/// execs. Extracted so tests can run it directly (without osascript) and
/// verify the FSM contracts: writes pidfile, drains stderr to log, removes
/// pidfile on exit, honours the sigfile for cooperative shutdown, and
/// brings up routing so packets actually flow through the tunnel.
#[doc(hidden)]
pub fn build_launcher_script(p: LauncherPaths<'_>) -> String {
    // Bypass IPs become a space-separated list embedded in the script.
    // We trust the supervisor to have validated these (they came out of
    // a DNS lookup of the active profile's address). Filter to safe chars
    // defensively anyway.
    let bypass_list = p
        .bypass_ips
        .iter()
        .filter(|ip| ip.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':'))
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        "#!/bin/bash\n\
         set -u\n\
         LOG={log:?}\n\
         PIDFILE={pid:?}\n\
         SIGFILE={sig:?}\n\
         BIN={bin:?}\n\
         IFACE={iface:?}\n\
         PROXY=\"socks5://{socks}\"\n\
         BYPASS_IPS=\"{bypass}\"\n\
         TUN_IP=\"198.18.0.1\"\n\
         \n\
         : > \"$LOG\"\n\
         chmod 644 \"$LOG\"\n\
         \n\
         # Diagnostic header so we can tell post-mortem what context the\n\
         # script ran in (uid, ppid, env, whether tun2socks even ran).\n\
         {{\n\
           echo \"--- nexray-tun launcher diag ---\"\n\
           echo \"date: $(date)\"\n\
           echo \"uid=$(id -u) gid=$(id -g) user=$(id -un)\"\n\
           echo \"pid=$$ ppid=$PPID\"\n\
           echo \"BIN=$BIN\"\n\
           echo \"IFACE=$IFACE TUN_IP=$TUN_IP\"\n\
           echo \"BYPASS_IPS=$BYPASS_IPS\"\n\
         }} >> \"$LOG\" 2>&1\n\
         \n\
         # Look up the original default gateway/interface BEFORE we touch\n\
         # routes. We need both for /32 bypass routes (per-host via gw) and\n\
         # to restore on teardown. If empty, skip bypass setup; routing\n\
         # will still install but xray's upstream connection may loop.\n\
         LOCAL_GW=$(/sbin/route -n get default 2>/dev/null | awk '/gateway:/ {{print $2}}')\n\
         LOCAL_IF=$(/sbin/route -n get default 2>/dev/null | awk '/interface:/ {{print $2}}')\n\
         echo \"LOCAL_GW=$LOCAL_GW LOCAL_IF=$LOCAL_IF\" >> \"$LOG\"\n\
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
         \n\
         # Bypass /32 routes: each proxy IP must reach the internet via the\n\
         # ORIGINAL default gateway, otherwise xray's upstream connection\n\
         # to it would route back into the tunnel and loop forever.\n\
         if [ -n \"$LOCAL_GW\" ]; then\n\
           for IP in $BYPASS_IPS; do\n\
             /sbin/route -n add -host \"$IP\" \"$LOCAL_GW\" >> \"$LOG\" 2>&1 \\\n\
               && echo \"bypass: $IP -> $LOCAL_GW\" >> \"$LOG\"\n\
           done\n\
         fi\n\
         \n\
         # Split-default trick: 0.0.0.0/1 + 128.0.0.0/1 covers all of\n\
         # 0.0.0.0/0 but is more specific than the existing default route,\n\
         # so it wins. Lets us point everything at utun without having to\n\
         # `route change default` (which is hard to roll back cleanly).\n\
         /sbin/route -n add -net 0.0.0.0/1 -interface \"$IFACE\" >> \"$LOG\" 2>&1\n\
         /sbin/route -n add -net 128.0.0.0/1 -interface \"$IFACE\" >> \"$LOG\" 2>&1\n\
         echo \"split-default routes installed via $IFACE\" >> \"$LOG\"\n\
         \n\
         # Cooperative shutdown loop. Polls every 0.3s.\n\
         while kill -0 \"$TUN_PID\" 2>/dev/null; do\n\
           if [ -e \"$SIGFILE\" ]; then\n\
             rm -f \"$SIGFILE\"\n\
             echo \"sigfile observed, sending SIGTERM\" >> \"$LOG\"\n\
             kill -TERM \"$TUN_PID\" 2>/dev/null || true\n\
             sleep 1\n\
             kill -KILL \"$TUN_PID\" 2>/dev/null || true\n\
             break\n\
           fi\n\
           sleep 0.3\n\
         done\n\
         \n\
         wait \"$TUN_PID\" 2>/dev/null\n\
         echo \"tun2socks exited with status $?\" >> \"$LOG\"\n\
         \n\
         # Tear down routes and addresses. We added these; we own removing\n\
         # them. Errors swallowed because some entries may have failed to\n\
         # install or already been removed.\n\
         /sbin/route -n delete -net 0.0.0.0/1 -interface \"$IFACE\" >> \"$LOG\" 2>&1 || true\n\
         /sbin/route -n delete -net 128.0.0.0/1 -interface \"$IFACE\" >> \"$LOG\" 2>&1 || true\n\
         if [ -n \"$LOCAL_GW\" ]; then\n\
           for IP in $BYPASS_IPS; do\n\
             /sbin/route -n delete -host \"$IP\" \"$LOCAL_GW\" >> \"$LOG\" 2>&1 || true\n\
           done\n\
         fi\n\
         /sbin/ifconfig \"$IFACE\" down >> \"$LOG\" 2>&1 || true\n\
         echo \"routing torn down\" >> \"$LOG\"\n\
         \n\
         rm -f \"$PIDFILE\"\n\
         exit 0\n",
        log = p.log,
        pid = p.pidfile,
        sig = p.sigfile,
        bin = p.binary,
        iface = p.iface,
        socks = p.socks_addr,
        bypass = bypass_list,
    )
}

/// Tail the per-session log file, feeding lines through the same sticky-
/// error pipeline as `drain_lines`. Stops when the pidfile vanishes (the
/// launcher's exit signal) or when EOF + 1s passes with no new data.
#[cfg(target_os = "macos")]
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
            let msg = if lower.contains("operation not permitted")
                && lower.contains("create tun")
            {
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
