//! Self-heal runtime helpers — Phase 7.
//!
//! When the app exits cleanly the supervisors remove their PID files. When
//! it crashes (force-kill, panic) the files are left behind pointing at
//! children that may still be alive. `scrub_orphans()` runs at boot, before
//! we hand the app to the user, and kills any survivors.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

/// Names of the PID files we manage. Add a new entry whenever a new
/// long-running supervisor is introduced.
pub const PID_FILES: &[&str] = &["xray.pid", "tun2socks.pid"];

/// Snapshot of a privileged TUN session, persisted to disk at enable time
/// so we can detect orphans at the next launch — i.e. cases where the
/// nexray host crashed AND the elevated launcher script crashed before its
/// own teardown ran. The launcher's own parent-pid watchdog handles the
/// 99% case (host dies → launcher tears down within ~300ms); this file is
/// the belt-and-braces audit trail for the rare cases where even that
/// doesn't run (power loss mid-teardown, SIGKILL targeting the launcher
/// specifically, etc.).
pub const TUN_SNAPSHOT_FILE: &str = "tun_snapshot.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunSnapshot {
    /// Wrapper PID — `osascript` on macOS, `pkexec` on Linux, the outer
    /// `powershell.exe` on Windows. We check this at boot via OS-level
    /// liveness probes; if it's gone, the previous session ended.
    pub launcher_pid: u32,
    pub iface: String,
    /// Sigfile path the launcher polls for cooperative teardown. Recovery
    /// touches it as a (probably no-op) belt-and-braces signal.
    pub sigfile: PathBuf,
    /// macOS-detached path tun2socks pidfile. Useful for detecting whether
    /// tun2socks itself was still running when the launcher died.
    pub pidfile: Option<PathBuf>,
    pub log: Option<PathBuf>,
    pub iface_file: Option<PathBuf>,
    /// Launcher-script file (.sh / .ps1) we wrote into temp_dir before
    /// spawning. The launcher rms it at clean exit; we rm it here on
    /// boot if it's lingering.
    pub script: Option<PathBuf>,
    pub since_ms: u64,
    pub platform: String,
}

/// Compute the runtime directory inside Tauri's app-data dir. Created on
/// first call; safe to call repeatedly.
pub fn runtime_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let data = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let dir = data.join("runtime");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

pub fn pid_file_path(app: &AppHandle, name: &str) -> Result<PathBuf, String> {
    Ok(runtime_dir(app)?.join(name))
}

pub fn tun_snapshot_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(runtime_dir(app)?.join(TUN_SNAPSHOT_FILE))
}

pub fn write_tun_snapshot(path: &PathBuf, snapshot: &TunSnapshot) {
    match serde_json::to_string_pretty(snapshot) {
        Ok(s) => {
            if let Err(e) = std::fs::write(path, s) {
                tracing::warn!(
                    target: "runtime",
                    "failed to persist TUN snapshot to {}: {e}",
                    path.display(),
                );
            }
        }
        Err(e) => tracing::warn!(target: "runtime", "TUN snapshot serialise failed: {e}"),
    }
}

pub fn delete_tun_snapshot(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
}

fn read_tun_snapshot(path: &PathBuf) -> Option<TunSnapshot> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Scan known PID files; for each, kill the recorded PID if still alive,
/// then remove the file. Errors are swallowed — self-heal is best-effort.
pub fn scrub_orphans(app: &AppHandle) {
    let Ok(dir) = runtime_dir(app) else { return };
    for name in PID_FILES {
        let path = dir.join(name);
        if !path.exists() {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                kill_pid_if_alive(pid);
                tracing::info!(
                    target: "runtime",
                    "scrubbed orphan PID {pid} from {}",
                    path.display(),
                );
            }
        }
        let _ = std::fs::remove_file(&path);
    }

    // TUN snapshot: if a previous session's privileged launcher died
    // without removing this file, its parent-pid watchdog presumably
    // already tore down routes (it runs when nexray dies — see launcher
    // scripts in tun.rs). The remaining concern is leftover /tmp files
    // and a stale snapshot record. Re-elevation to forcibly tear down
    // routes when even the launcher missed cleanup is a future Layer 3.
    let snap_path = dir.join(TUN_SNAPSHOT_FILE);
    if snap_path.exists() {
        if let Some(snap) = read_tun_snapshot(&snap_path) {
            if pid_alive(snap.launcher_pid) {
                tracing::warn!(
                    target: "runtime",
                    "TUN snapshot reports launcher PID {} still alive across launches \
                     — touching sigfile so it can tear down on its own",
                    snap.launcher_pid,
                );
                let _ = std::fs::write(&snap.sigfile, b"stop");
            } else {
                tracing::warn!(
                    target: "runtime",
                    "previous TUN session ended uncleanly (launcher PID {} on iface {} is gone) \
                     — cleaning leftover temp files",
                    snap.launcher_pid,
                    snap.iface,
                );
                for p in [&snap.pidfile, &snap.log, &snap.iface_file, &snap.script]
                    .into_iter()
                    .flatten()
                {
                    let _ = std::fs::remove_file(p);
                }
                let _ = std::fs::remove_file(&snap.sigfile);
            }
        }
        let _ = std::fs::remove_file(&snap_path);
    }
}

#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    std::process::Command::new("/bin/ps")
        .args(["-p", &pid.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn pid_alive(pid: u32) -> bool {
    use std::os::windows::process::CommandExt;
    let output = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout);
            s.contains(&format!("\"{pid}\""))
        }
        _ => false,
    }
}

fn kill_pid_if_alive(pid: u32) {
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .status();
    }
}
