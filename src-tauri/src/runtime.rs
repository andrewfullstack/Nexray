//! Self-heal runtime helpers — Phase 7.
//!
//! When the app exits cleanly the supervisors remove their PID files. When
//! it crashes (force-kill, panic) the files are left behind pointing at
//! children that may still be alive. `scrub_orphans()` runs at boot, before
//! we hand the app to the user, and kills any survivors.

use std::path::PathBuf;

use tauri::{AppHandle, Manager};

/// Names of the PID files we manage. Add a new entry whenever a new
/// long-running supervisor is introduced.
pub const PID_FILES: &[&str] = &["xray.pid", "tun2socks.pid"];

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
