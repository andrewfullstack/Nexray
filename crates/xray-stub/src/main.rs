//! Test-only sidecar that mimics enough of xray-core for the supervisor to
//! drive a complete lifecycle without bundling real xray. Behaviour:
//!
//! 1. Read stdin to EOF.
//! 2. If the input parses as JSON and exposes `inbounds[0].port`, bind a
//!    TCP listener on `127.0.0.1:<port>` so the supervisor's TCP probe
//!    (Phase 3+) sees a live listener.
//! 3. Print `xray-stub ready` on stderr — the supervisor pattern-matches
//!    this to flip `Connecting → Connected`.
//! 4. Sleep until killed by the parent.
//!
//! Per DEVELOPMENT.md §11: `expect`/`unwrap` are allowed in `main`. This is
//! a `main` for a test binary, so we use them freely.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::thread;
use std::time::Duration;

fn main() {
    let mut buf = String::new();
    let _ = io::stdin().lock().read_to_string(&mut buf);

    let listener: Option<TcpListener> = serde_json::from_str::<serde_json::Value>(&buf)
        .ok()
        .and_then(|v| v["inbounds"][0]["port"].as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .and_then(|port| TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).ok());

    if let Some(l) = &listener {
        // Spawn a thread that accepts and immediately drops connections so
        // the supervisor's probe doesn't get RST in flight.
        let l = l.try_clone().expect("clone listener");
        thread::spawn(move || {
            for stream in l.incoming() {
                drop(stream);
            }
        });
    }

    eprintln!("xray-stub ready");

    // Block until the parent kills us. The 60-second sleep makes us robust
    // against `cargo test`'s default 60s test timeout (we'll be killed long
    // before this returns).
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}
