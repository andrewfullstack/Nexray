//! TUN-mode supervisor — Phase 6.
//!
//! Spawns the bundled `tun2socks` binary with the SOCKS inbound endpoint of
//! our xray sidecar so OS-level traffic flows through the proxy. Mirrors the
//! `XraySidecar` lifecycle shape (start / stop / status, Drop kills the child)
//! so the IPC layer can poll uniformly.
//!
//! Privilege escalation: tun2socks needs admin rights to create the kernel
//! interface and rewrite routes. Phase 6 detects "needs elevation" failures
//! and surfaces them as `state: failed`; the proper SMJobBless / UAC helper
//! flow is a Phase 7 polish item — see docs/ARCHITECTURE.md.
//!
//! Route management: tun2socks itself sets up the interface address and
//! brings it up. The default-route swap (so all traffic captures) is handled
//! per-OS by tun2socks's `-tunRoute` flag. We don't shell out to `route`
//! ourselves — that responsibility lives in tun2socks.

use std::path::PathBuf;
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
    child: Option<Child>,
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
            child: None,
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
    /// `127.0.0.1:10808`). Returns immediately after spawn — caller should
    /// poll `status()` for the transition into `Active`.
    pub fn enable(&self, socks_addr: &str, iface_name: &str) -> Result<TunStatus, TunError> {
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

        // Standard tun2socks invocation: SOCKS5 proxy + a TUN device name.
        // tun2socks creates the interface and brings it up; the OS-specific
        // route swap is `-tunRoute auto` style (varies by tun2socks fork).
        // We rely on the bundled binary's defaults for route handling.
        let mut cmd = Command::new(&inner.binary_path);
        cmd.args([
            "-device",
            iface_name,
            "-proxy",
            &format!("socks5://{socks_addr}"),
            "-loglevel",
            "warn",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(TunError::Spawn)?;

        // Drain stderr to tracing in a background thread so the supervisor
        // doesn't block on a full pipe. We also surface the last line as
        // `last_error` if the child later exits.
        if let Some(stderr) = child.stderr.take() {
            let inner_arc = Arc::clone(&self.inner);
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader};
                let reader = BufReader::new(stderr);
                for line in reader.lines().map_while(Result::ok) {
                    if line.trim().is_empty() {
                        continue;
                    }
                    tracing::info!(target: "tun2socks", "{line}");
                    let mut inner = lock(&inner_arc);
                    // Sticky-first-error: keep the FATAL/ERROR line so the
                    // user sees "operation not permitted" rather than a
                    // stack-trace tail. Non-error lines (info logs) don't
                    // touch last_error.
                    let lower = line.to_ascii_lowercase();
                    let is_error = lower.contains("fatal") || lower.contains("error");
                    if is_error && inner.last_error.is_none() {
                        // Annotate the most common privilege failure so the
                        // UI can show "needs sudo" instead of a kernel
                        // primitive's wording.
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
            });
        }

        let pid = child.id();
        inner.state = TunState::Starting;
        inner.child = Some(child);
        inner.interface_name = Some(iface_name.to_string());
        inner.since_ms = Some(now_ms());
        inner.last_error = None;
        if let Some(p) = inner.pid_file.as_ref() {
            let _ = std::fs::write(p, pid.to_string());
        }
        Ok(snapshot(&inner))
    }

    pub fn disable(&self) -> Result<TunStatus, TunError> {
        let mut inner = lock(&self.inner);
        inner.state = TunState::Stopping;
        if let Some(mut child) = inner.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(p) = inner.pid_file.as_ref() {
            let _ = std::fs::remove_file(p);
        }
        inner.state = TunState::Disabled;
        inner.interface_name = None;
        inner.since_ms = None;
        inner.last_error = None;
        Ok(snapshot(&inner))
    }

    pub fn status(&self) -> TunStatus {
        let mut inner = lock(&self.inner);
        if let Some(child) = inner.child.as_mut() {
            if let Ok(Some(status)) = child.try_wait() {
                inner.state = TunState::Failed;
                if inner.last_error.is_none() {
                    inner.last_error = Some(format!("tun2socks exited: {status}"));
                }
                inner.child = None;
            }
        }
        snapshot(&inner)
    }
}

impl Drop for TunSupervisor {
    fn drop(&mut self) {
        let _ = self.disable();
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
