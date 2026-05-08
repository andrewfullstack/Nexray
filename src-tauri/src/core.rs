//! xray-core sidecar lifecycle FSM.
//!
//! - `start(profile_id, socks_port, config_json)` — spawns the bundled xray
//!   binary with `-config stdin:`, pipes the JSON config in, transitions
//!   `Disconnected → Connecting`. The first non-empty stderr line
//!   transitions `Connecting → Connected`.
//! - `poll()` — observes `child.try_wait()`. Unexpected exit moves us to
//!   `Crashed`. The supervisor never auto-restarts; per Phase 2 acceptance
//!   the user must call `connect` again.
//! - `stop()` — kills the child and resets to `Disconnected`.
//! - `Drop` — best-effort `stop` so app exit terminates the child within ~3s.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use nexray_core::{ConnectionState, ConnectionStatus};
use thiserror::Error;

/// Process supervisor for the xray-core sidecar. Cheaply cloneable: all
/// instances share the same backing state through an `Arc<Mutex<Inner>>`.
#[derive(Clone)]
pub struct XraySidecar {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    binary_path: PathBuf,
    args: Vec<String>,
    state: ConnectionState,
    child: Option<Child>,
    profile_id: Option<String>,
    socks_port: Option<u16>,
    since_ms: Option<u64>,
    /// Trailing line from the child's stderr; surfaced as `last_error` when
    /// the child exits unexpectedly.
    last_stderr_line: Option<String>,
    last_error: Option<String>,
    /// Optional PID-file path. When set, `start` writes the child's PID and
    /// `stop`/Drop remove the file. The boot-time scrubber in `lib.rs` looks
    /// for this file to terminate orphans from a prior crash.
    pid_file: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub enum SidecarError {
    #[error("xray sidecar already running; call disconnect first")]
    AlreadyRunning,
    #[error("failed to spawn xray sidecar: {0}")]
    Spawn(std::io::Error),
    #[error("io error talking to xray sidecar: {0}")]
    Io(std::io::Error),
    #[error("xray sidecar exposed no stderr handle")]
    NoStderr,
}

impl XraySidecar {
    /// Construct a supervisor for `binary_path`, with the given args appended
    /// to the spawn command. For real xray-core: `["-config", "stdin:"]`.
    /// For the test stub: `[]`.
    pub fn new(binary_path: PathBuf, args: Vec<String>) -> Self {
        let inner = Inner {
            binary_path,
            args,
            state: ConnectionState::Disconnected,
            child: None,
            profile_id: None,
            socks_port: None,
            since_ms: None,
            last_stderr_line: None,
            last_error: None,
            pid_file: None,
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Track this supervisor's child PID in `path`, written on `start` and
    /// removed on `stop`/Drop. `lib.rs::setup` scrubs leftover files at boot.
    pub fn set_pid_file(&self, path: PathBuf) {
        lock(&self.inner).pid_file = Some(path);
    }

    /// Path to the xray binary this supervisor spawns. Used by the
    /// stats client to reach the same binary for `xray api statsquery`
    /// shell-outs (mismatching xray versions could speak different
    /// protobuf shapes).
    pub fn binary_path(&self) -> PathBuf {
        lock(&self.inner).binary_path.clone()
    }

    /// PID of the live child, if any. Returns `None` when the supervisor
    /// is `Disconnected`/`Crashed` or before `start` has spawned anything.
    /// Used by integration tests to target the exact child without relying
    /// on `pkill -f` (which would also reap siblings spawned by parallel
    /// tests sharing the same binary name).
    pub fn child_pid(&self) -> Option<u32> {
        lock(&self.inner).child.as_ref().map(|c| c.id())
    }

    pub fn start(
        &self,
        profile_id: String,
        socks_port: u16,
        config_json: String,
    ) -> Result<(), SidecarError> {
        let mut inner = lock(&self.inner);
        if matches!(
            inner.state,
            ConnectionState::Connecting | ConnectionState::Connected
        ) {
            return Err(SidecarError::AlreadyRunning);
        }

        tracing::info!(
            target: "xray-spawn",
            "spawning {:?} with args {:?}",
            inner.binary_path,
            inner.args,
        );
        let mut command = Command::new(&inner.binary_path);
        command
            .args(&inner.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|e| {
            tracing::error!(target: "xray-spawn", "spawn failed: {e}");
            SidecarError::Spawn(e)
        })?;
        tracing::info!(target: "xray-spawn", "spawned child pid={}", child.id());

        // Immediately check if the child is already dead. A successful
        // `Command::spawn()` doesn't guarantee the child stayed alive — on
        // macOS, Gatekeeper / quarantine / AMFI can SIGKILL the process
        // milliseconds after exec. If that happens, we want a clear log
        // line, not a silent supervisor stuck in Connecting.
        std::thread::sleep(std::time::Duration::from_millis(50));
        match child.try_wait() {
            Ok(Some(s)) => {
                tracing::error!(
                    target: "xray-spawn",
                    "child exited within 50ms of spawn: {s} — likely killed by macOS security",
                );
            }
            Ok(None) => {
                tracing::info!(target: "xray-spawn", "child still alive after 50ms");
            }
            Err(e) => {
                tracing::warn!(target: "xray-spawn", "try_wait error: {e}");
            }
        }

        // xray-core writes its startup banner ("Xray X.Y.Z started", config-
        // load progress, deprecation warnings) to **stdout**, and runtime
        // errors to **stderr**. Capture both so the supervisor's Connecting
        // → Connected transition fires on the first stdout line, and crashes
        // surface a useful `last_error` from stderr.
        let stderr = child.stderr.take().ok_or(SidecarError::NoStderr)?;
        let stdout = child.stdout.take();
        let stdin_handle = child.stdin.take();

        // Pipe the config to xray's stdin in a background thread. The
        // materialized config can exceed macOS's 16 KB pipe buffer (with
        // 700+ rules from `rules.conf`), in which case `write_all` would
        // block the IPC handler until xray finished draining. By moving
        // the write off the command-handler thread, `start` returns
        // immediately; if the write fails (e.g. xray crashed before
        // reading), the error surfaces through `last_error` and the
        // child's exit status.
        if let Some(mut stdin) = stdin_handle {
            let inner_arc = Arc::clone(&self.inner);
            let bytes_to_write = config_json.len();
            thread::spawn(move || {
                tracing::info!(target: "xray-stdin", "writer thread starting, will pipe {} bytes", bytes_to_write);
                let started = std::time::Instant::now();
                match stdin.write_all(config_json.as_bytes()) {
                    Ok(()) => tracing::info!(
                        target: "xray-stdin",
                        "wrote {} bytes in {}ms",
                        bytes_to_write,
                        started.elapsed().as_millis(),
                    ),
                    Err(e) => {
                        tracing::warn!(target: "xray-stdin", "write_all failed: {e}");
                        let mut inner = lock(&inner_arc);
                        inner.last_error = Some(format!("config pipe error: {e}"));
                    }
                }
                // Flush + drop closes the pipe → xray sees EOF and proceeds.
                let _ = std::io::Write::flush(&mut stdin);
                drop(stdin);
                tracing::info!(target: "xray-stdin", "stdin closed");
            });
        } else {
            tracing::error!(target: "xray-stdin", "child.stdin was None — config will never be written!");
        }

        let pid = child.id();
        inner.state = ConnectionState::Connecting;
        inner.child = Some(child);
        inner.profile_id = Some(profile_id);
        inner.socks_port = Some(socks_port);
        inner.since_ms = Some(now_ms());
        inner.last_stderr_line = None;
        inner.last_error = None;
        if let Some(p) = inner.pid_file.as_ref() {
            let _ = std::fs::write(p, pid.to_string());
        }
        drop(inner);

        let stderr_arc = Arc::clone(&self.inner);
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                if line.trim().is_empty() {
                    continue;
                }
                if is_stats_poll_noise(&line) {
                    continue;
                }
                tracing::warn!(target: "xray", "{line}");
                let mut inner = lock(&stderr_arc);
                inner.last_stderr_line = Some(line);
                if matches!(inner.state, ConnectionState::Connecting) {
                    inner.state = ConnectionState::Connected;
                }
            }
        });

        if let Some(stdout) = stdout {
            let stdout_arc = Arc::clone(&self.inner);
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines().map_while(Result::ok) {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if is_stats_poll_noise(&line) {
                        continue;
                    }
                    tracing::info!(target: "xray", "{line}");
                    let mut inner = lock(&stdout_arc);
                    // xray-core writes its "Failed to start: …" rejection
                    // to **stdout**, not stderr. Capture it as last_error
                    // material so the UI's red banner shows the real reason
                    // when the supervisor later flips to Crashed.
                    if line.contains("Failed to start")
                        || line.contains("[Error]")
                        || line.contains("invalid field")
                    {
                        inner.last_stderr_line = Some(line.clone());
                    }
                    if matches!(inner.state, ConnectionState::Connecting) {
                        inner.state = ConnectionState::Connected;
                    }
                }
            });
        }

        Ok(())
    }

    pub fn stop(&self) -> Result<(), SidecarError> {
        let mut inner = lock(&self.inner);
        if let Some(mut child) = inner.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(p) = inner.pid_file.as_ref() {
            let _ = std::fs::remove_file(p);
        }
        inner.state = ConnectionState::Disconnected;
        inner.profile_id = None;
        inner.socks_port = None;
        inner.since_ms = None;
        inner.last_error = None;
        inner.last_stderr_line = None;
        Ok(())
    }

    /// Snapshot the current status. Side effect: if the child exited
    /// unexpectedly, transitions the state to `Crashed`. Cheap; safe to call
    /// from a 1Hz UI poll.
    pub fn status(&self) -> ConnectionStatus {
        let mut inner = lock(&self.inner);
        if let Some(child) = inner.child.as_mut() {
            match child.try_wait() {
                Ok(Some(exit)) => {
                    tracing::error!(
                        target: "xray-spawn",
                        "child exited: {exit:?} (last_stderr_line={:?})",
                        inner.last_stderr_line,
                    );
                    inner.state = ConnectionState::Crashed;
                    inner.last_error = inner.last_stderr_line.clone();
                    inner.child = None;
                }
                Ok(None) => {
                    // still alive, no transition
                }
                Err(e) => {
                    tracing::warn!(target: "xray-spawn", "try_wait error: {e}");
                }
            }
        }
        ConnectionStatus {
            state: inner.state,
            profile_id: inner.profile_id.clone(),
            socks_port: inner.socks_port,
            since_ms: inner.since_ms,
            last_error: inner.last_error.clone(),
        }
    }
}

// NOTE: `XraySidecar` deliberately does NOT implement `Drop`. The struct is
// `#[derive(Clone)]`, and every IPC command (plus the Tauri `State<T>`
// borrow) ends up holding a clone briefly. Tearing down the child on every
// clone drop would kill xray the moment a command function returned. The
// process cleanup lives in `impl Drop for Inner` below, which only fires
// when the last `Arc<Mutex<Inner>>` goes away — i.e. on app exit when
// `AppState.sidecar` is dropped.

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(p) = self.pid_file.as_ref() {
            let _ = std::fs::remove_file(p);
        }
    }
}

// Lock poisoning indicates an upstream panic; we choose to surface that as
// a panic ourselves rather than recover into an undefined state.
#[allow(clippy::expect_used)]
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().expect("xray sidecar mutex poisoned")
}

#[allow(clippy::expect_used)]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock pre-1970?")
        .as_millis() as u64
}

/// True when an xray log line is a routine per-connection routing
/// decision — the high-volume `accepted tcp:HOST:PORT [INBOUND ->
/// OUTBOUND]` and `accepted udp:HOST:PORT [...]` patterns. xray-core
/// emits one such INFO line per accepted connection, including:
///
///   - Our 1Hz / 3s Stats API polls (`[api-in -> api]`).
///   - Every browser tab's connections through the SOCKS inbound.
///   - Every ad-block hit (`[socks-in -> block]`) from the rules file.
///
/// The speedometer and egress check already give visual confirmation
/// of traffic flow, so dropping these lines from the wrapper log is
/// pure noise reduction. Errors (stderr) and one-shot startup banners
/// still surface — only the per-connection chatter is suppressed.
fn is_stats_poll_noise(line: &str) -> bool {
    line.contains("accepted tcp:") || line.contains("accepted udp:")
}

#[cfg(test)]
mod core_tests {
    use super::*;

    #[test]
    fn filter_matches_actual_xray_routing_logs() {
        // Captured: stats-poll RPC against the api inbound.
        let stats_poll = "2026/05/08 20:11:03.899910 from 127.0.0.1:55682 accepted tcp:127.0.0.1:55522 [api-in -> api]";
        assert!(is_stats_poll_noise(stats_poll));

        // Captured: real ad-block hit through the SOCKS inbound.
        let ad_block = "2026/05/08 20:39:03.872410 from tcp:127.0.0.1:56856 accepted tcp:live.primis.tech:443 [socks-in -> block]";
        assert!(is_stats_poll_noise(ad_block));

        // Captured: real proxied traffic.
        let proxied = "2026/05/08 20:39:03.872410 from tcp:127.0.0.1:56789 accepted tcp:example.com:443 [socks-in -> proxy]";
        assert!(is_stats_poll_noise(proxied));

        // UDP traffic via TUN gets the same treatment.
        let udp = "2026/05/08 20:39:03.872410 from udp:127.0.0.1:56000 accepted udp:1.1.1.1:53 [tun-in -> proxy]";
        assert!(is_stats_poll_noise(udp));

        // Sanity: startup banners and warnings DON'T match — those
        // lines (one-shot, surface useful boot info or errors) keep
        // their normal log level.
        let startup = "Xray 25.5.0 (Xray, Penetrates Everything.) Custom (go1.22.5 darwin/arm64)";
        assert!(!is_stats_poll_noise(startup));
        let started = "2026/05/08 20:39:00.000000 [Info] core/server.go:175 starting Xray ...";
        assert!(!is_stats_poll_noise(started));
    }
}
