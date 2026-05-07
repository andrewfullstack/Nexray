//! Reproduces the exact connect-command code path against the REAL xray
//! binary the user has installed, so we can see what xray says when our
//! supervisor pipes the materialized config in.
//!
//! Ignored by default — run explicitly when debugging:
//!   cargo test -p nexray --test repro_connect -- --ignored --nocapture
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nexray_core::xray_config::{default_routing_settings, materialize, XrayConfigOptions};
use nexray_core::{rules_conf, Alpn, CdnWsProfile, Fingerprint, Profile};

const REAL_XRAY: &str =
    "/Users/yangqi/Documents/github/nexray/src-tauri/binaries/Xray-macos-arm64-v8a/xray";
const RULES_CONF: &str = "/Users/yangqi/Library/Application Support/dev.nexray.app/rules.conf";

fn pick_loopback_port() -> u16 {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn fixture_profile() -> Profile {
    // Same shape as the user's saved JSON-imported server.
    Profile::CdnWs(CdnWsProfile {
        id: "repro".into(),
        name: "repro".into(),
        remark: None,
        address: "3180e8f7.mykv-evj.pages.dev".into(),
        port: 443,
        uuid: "77e24b83-495a-42e6-8eb8-c4cffa8b13b6".into(),
        host: "3180e8f7.mykv-evj.pages.dev".into(),
        path: "/".into(),
        sni: "3180e8f7.mykv-evj.pages.dev".into(),
        alpn: vec![Alpn::H2, Alpn::Http11],
        fingerprint: Fingerprint::Chrome,
    })
}

fn build_config_json() -> (String, usize, usize) {
    let rules_text = std::fs::read_to_string(RULES_CONF).unwrap_or_default();
    let conf = rules_conf::parse(&rules_text);
    let translated = rules_conf::translate(&conf);
    let extra_count = translated.rules.len();

    // Match the connect command's options exactly, including the stats
    // inbound on a random loopback port.
    let stats_port = pick_loopback_port();
    let cfg = materialize(
        &fixture_profile(),
        &XrayConfigOptions {
            socks_port: 0, // overridden below
            stats_port: Some(stats_port),
            log_level: "warning",
            routing: default_routing_settings(),
            extra_rules: translated.rules,
        },
    )
    .expect("materialize");
    let json = serde_json::to_string(&cfg).expect("serialize");
    let len = json.len();
    (json, len, extra_count)
}

fn replace_port(json: &str, port: u16) -> String {
    json.replace(r#""port":0"#, &format!(r#""port":{port}"#))
}

#[test]
#[ignore]
fn repro_connect_against_real_xray() {
    println!("\n========== nexray Connect repro ==========\n");

    let xray = PathBuf::from(REAL_XRAY);
    assert!(xray.exists(), "real xray missing at {}", xray.display());

    let socks_port = pick_loopback_port();
    let (json_template, raw_size, extra_rules_count) = build_config_json();
    let config_json = replace_port(&json_template, socks_port);

    println!("rules.conf rules translated → xray:  {extra_rules_count}");
    println!("materialized config size (bytes):    {raw_size}");
    println!("SOCKS port chosen:                   {socks_port}");
    println!();

    println!("--- spawning xray ---");
    let mut child = Command::new(&xray)
        .args(["-config", "stdin:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    // Mirror our supervisor: write config in a background thread.
    let mut stdin = child.stdin.take().unwrap();
    let cfg_bytes = config_json.into_bytes();
    thread::spawn(move || {
        let n = cfg_bytes.len();
        let started = Instant::now();
        if let Err(e) = stdin.write_all(&cfg_bytes) {
            println!(
                "[writer] write_all FAILED after {}ms: {e}",
                started.elapsed().as_millis()
            );
        } else {
            println!(
                "[writer] wrote {n} bytes in {}ms",
                started.elapsed().as_millis()
            );
        }
        drop(stdin);
    });

    // Stream stdout + stderr to test output.
    use std::io::{BufRead, BufReader};
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            println!("[xray stdout] {line}");
        }
    });
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            println!("[xray stderr] {line}");
        }
    });

    // Watch for SOCKS port + child status for up to 5s.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut port_seen_at: Option<Duration> = None;
    let started = Instant::now();
    let mut last_port_check = Instant::now();
    let mut child_exited: Option<std::process::ExitStatus> = None;
    while Instant::now() < deadline {
        if let Ok(Some(s)) = child.try_wait() {
            child_exited = Some(s);
            break;
        }
        if last_port_check.elapsed() > Duration::from_millis(100) {
            last_port_check = Instant::now();
            if port_seen_at.is_none() {
                let probe = TcpStream::connect_timeout(
                    &SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port).into(),
                    Duration::from_millis(50),
                );
                if probe.is_ok() {
                    port_seen_at = Some(started.elapsed());
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    println!();
    println!("--- result after {}ms ---", started.elapsed().as_millis());
    match port_seen_at {
        Some(d) => println!("✅ SOCKS port {socks_port} reachable @ {}ms", d.as_millis()),
        None => println!("❌ SOCKS port {socks_port} never came up"),
    }
    match child_exited {
        Some(s) => println!("⚠️  xray exited: {s}"),
        None => println!("xray still running"),
    }

    // If the port is up, try a real curl through it so we know the proxy
    // proxies (not just binds).
    if port_seen_at.is_some() {
        let curl = Command::new("/usr/bin/curl")
            .args([
                "--max-time",
                "8",
                "--silent",
                "--proxy",
                &format!("socks5h://127.0.0.1:{socks_port}"),
                "https://ifconfig.me",
            ])
            .output();
        match curl {
            Ok(out) if out.status.success() => {
                let body = String::from_utf8_lossy(&out.stdout);
                println!("✅ curl through proxy OK: {}", body.trim());
            }
            Ok(out) => {
                println!(
                    "❌ curl exited {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            Err(e) => println!("❌ curl spawn failed: {e}"),
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    // Give threads a moment to flush.
    thread::sleep(Duration::from_millis(300));
    println!("\n========== end repro ==========\n");
}
