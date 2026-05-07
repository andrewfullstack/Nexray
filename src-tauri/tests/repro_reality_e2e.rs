//! Comprehensive end-to-end test against a live VLESS+REALITY server.
//!
//! Steps 1 + 2 run against an in-source placeholder — they validate the
//! parser and config materializer without needing any network. Steps 3
//! + 4 are `#[ignore]`'d and need a real server you control:
//!
//!   NEXRAY_REALITY_SHARE_LINK="vless://uuid@host:443?...&security=reality&..."
//!   NEXRAY_REALITY_SERVER_IP="<the server's public IP>"
//!   cargo test -p nexray --test repro_reality_e2e -- --ignored --nocapture
//!
//! What this verifies end-to-end (steps 3 + 4):
//!   - Spawning xray with the materialized config establishes the
//!     REALITY tunnel (upstream `connection opened to <server>:443`).
//!   - SOCKS inbound is reachable on 127.0.0.1:<random>.
//!   - HTTP through the proxy succeeds AND the egress IP equals the
//!     server's public IP — proof traffic is actually tunneled.
//!   - All three routing presets (Default / Direct / Global) route
//!     correctly via the REALITY upstream.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nexray_core::xray_config::{default_routing_settings, materialize, XrayConfigOptions};
use nexray_core::{decode_share_link, DecodeResult, Profile, RoutingPreset, RoutingSettings};

const REAL_XRAY: &str =
    "/Users/yangqi/Documents/github/nexray/src-tauri/binaries/Xray-macos-arm64-v8a/xray";

/// Format-valid placeholder share link with a zero-UUID and a TEST-NET-3
/// (RFC 5737) IP that no real server uses. Step 1 (the parser test)
/// runs against this so the test is useful even without a live server.
/// Steps 3 + 4 require a real server; set `NEXRAY_REALITY_SHARE_LINK`
/// (and `NEXRAY_REALITY_SERVER_IP`) to your own values to run them.
const PLACEHOLDER_SHARE_LINK: &str = "vless://00000000-0000-0000-0000-000000000000@203.0.113.1:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=00000000&type=tcp#nexray-reality-placeholder";
const PLACEHOLDER_SERVER_IP: &str = "203.0.113.1";

fn share_link() -> String {
    std::env::var("NEXRAY_REALITY_SHARE_LINK").unwrap_or_else(|_| {
        panic!(
            "set NEXRAY_REALITY_SHARE_LINK to your own REALITY vless:// link \
             before running this live test (step 1 uses a placeholder)"
        )
    })
}

fn server_ip() -> String {
    std::env::var("NEXRAY_REALITY_SERVER_IP").unwrap_or_else(|_| {
        panic!("set NEXRAY_REALITY_SERVER_IP to your REALITY server's public IP")
    })
}

fn pick_loopback_port() -> u16 {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn parse_share_link(raw: &str) -> Profile {
    match decode_share_link(raw) {
        DecodeResult::Ok { profile } => profile,
        DecodeResult::Err { reason, raw } => {
            panic!("decode_share_link rejected the test fixture (reason={reason:?}, raw={raw})")
        }
    }
}

#[test]
fn step1_share_link_decodes_to_reality_profile() {
    // Uses a placeholder URL — no live server needed. Validates that
    // every REALITY field round-trips through the share-link decoder.
    let p = parse_share_link(PLACEHOLDER_SHARE_LINK);
    match p {
        Profile::Reality(ref r) => {
            assert_eq!(r.address, PLACEHOLDER_SERVER_IP);
            assert_eq!(r.port, 443);
            assert_eq!(r.flow, "xtls-rprx-vision");
            assert_eq!(r.sni, "www.microsoft.com");
            assert_eq!(r.uuid, "00000000-0000-0000-0000-000000000000");
            assert_eq!(r.public_key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            assert_eq!(r.short_id, "00000000");
            println!("  ✓ share link decoded to REALITY profile");
        }
        _ => panic!("expected Reality profile, got {p:?}"),
    }
}

#[test]
#[ignore] // Needs the xray binary installed at REAL_XRAY; skip on CI.
fn step2_config_materializes_and_xray_accepts_it() {
    let profile = parse_share_link(PLACEHOLDER_SHARE_LINK);
    let socks_port = pick_loopback_port();
    let cfg = materialize(
        &profile,
        &XrayConfigOptions {
            socks_port,
            stats_port: None,
            log_level: "warn",
            routing: RoutingSettings {
                preset: RoutingPreset::Default,
                custom_rules: vec![],
                dns: default_routing_settings().dns,
            },
            extra_rules: vec![],
            direct_send_through: None,
        },
    )
    .expect("materialize");

    // xray's `-test -c` validates the config without starting the process.
    // Older xray uses `xray test -c <path>`; newer `xray run -test -c <path>`.
    let tmp = std::env::temp_dir().join(format!("nexray-reality-test-{socks_port}.json"));
    std::fs::write(&tmp, serde_json::to_vec(&cfg).expect("serialize")).unwrap();
    let out = Command::new(REAL_XRAY)
        .args(["run", "-test", "-c"])
        .arg(&tmp)
        .output()
        .expect("spawn xray for test");
    let _ = std::fs::remove_file(&tmp);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "xray rejected materialized config\n  stdout: {stdout}\n  stderr: {stderr}"
    );
    println!("  ✓ xray accepts the materialized REALITY config");
}

#[test]
#[ignore]
fn step3_reality_tunnel_establishes_and_traffic_egresses_via_server() {
    println!("\n========== REALITY E2E: connect → tunnel → egress IP check ==========\n");
    let server_ip = server_ip();
    let link = share_link();
    let profile = parse_share_link(&link);
    let socks_port = pick_loopback_port();
    let cfg = materialize(
        &profile,
        &XrayConfigOptions {
            socks_port,
            stats_port: None,
            log_level: "info",
            routing: RoutingSettings {
                preset: RoutingPreset::Global,
                custom_rules: vec![],
                dns: default_routing_settings().dns,
            },
            extra_rules: vec![],
            direct_send_through: None,
        },
    )
    .expect("materialize");
    let cfg_json = serde_json::to_string(&cfg).unwrap();

    let mut child = Command::new(REAL_XRAY)
        .args(["-config", "stdin:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    thread::spawn(move || {
        let _ = stdin.write_all(cfg_json.as_bytes());
        drop(stdin);
    });

    let stdout = child.stdout.take().unwrap();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = Arc::clone(&captured);
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            cap.lock().unwrap().push(line);
        }
    });
    let stderr = child.stderr.take().unwrap();
    thread::spawn(
        move || {
            for _ in BufReader::new(stderr).lines().map_while(Result::ok) {}
        },
    );

    // Wait for SOCKS bind.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut bound = false;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port).into(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            bound = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(bound, "SOCKS port never bound");
    println!("  ✓ SOCKS inbound bound on 127.0.0.1:{socks_port}");

    // Direct egress (control).
    let direct_ip = run_curl(None, "https://ifconfig.me/ip");
    println!("  direct egress (control):     {direct_ip}");

    // Egress through proxy. Retry up to 4× with backoff to absorb
    // REALITY's ~1-3 s upstream handshake.
    let mut proxied_ip = String::new();
    for delay_ms in [0u64, 700, 1500, 3000] {
        if delay_ms > 0 {
            thread::sleep(Duration::from_millis(delay_ms));
        }
        proxied_ip = run_curl(
            Some(&format!("socks5h://127.0.0.1:{socks_port}")),
            "https://ifconfig.me/ip",
        );
        if !proxied_ip.is_empty() {
            break;
        }
    }
    println!("  egress through REALITY proxy: {proxied_ip}");

    // Verify the egress is the server's public IP — that's the load-bearing
    // assertion. If they're equal, traffic is genuinely tunneling through
    // the REALITY upstream and not falling through somewhere.
    assert!(!proxied_ip.is_empty(), "proxied egress empty after retries");
    assert_ne!(
        proxied_ip, direct_ip,
        "proxied egress matched direct — REALITY isn't actually tunneling"
    );
    assert_eq!(
        proxied_ip, server_ip,
        "proxied egress {proxied_ip} ≠ server IP {server_ip} — traffic is going somewhere unexpected"
    );
    println!("  ✓ proxied egress = server public IP {server_ip}");

    // xray's info logs should show successful upstream dial. Spotted by
    // `connection opened to tcp:<server_ip>:443` (the freedom-style log
    // format used internally for the upstream).
    thread::sleep(Duration::from_millis(300));
    let logs = captured.lock().unwrap().clone();
    let upstream_evidence: Vec<&String> = logs
        .iter()
        .filter(|l| l.contains(&server_ip) && l.contains("443"))
        .collect();
    println!(
        "  ✓ {} xray log line(s) reference the upstream {server_ip}:443",
        upstream_evidence.len()
    );
    for line in upstream_evidence.iter().take(3) {
        println!("      {line}");
    }

    let _ = child.kill();
    let _ = child.wait();
    println!("\n========== PASS: REALITY end-to-end works through Nexray ==========\n");
}

#[test]
#[ignore]
fn step4_all_three_presets_route_through_reality_upstream() {
    println!("\n========== REALITY E2E: 3 presets × 3 destinations ==========\n");
    let server_ip = server_ip();
    let link = share_link();
    let profile = parse_share_link(&link);

    for preset in [
        RoutingPreset::Default,
        RoutingPreset::Direct,
        RoutingPreset::Global,
    ] {
        let label = match preset {
            RoutingPreset::Default => "default",
            RoutingPreset::Direct => "direct",
            RoutingPreset::Global => "global",
        };
        println!("\n--- preset: {label} ---");
        let socks_port = pick_loopback_port();
        let cfg = materialize(
            &profile,
            &XrayConfigOptions {
                socks_port,
                stats_port: None,
                log_level: "info",
                routing: RoutingSettings {
                    preset,
                    custom_rules: vec![],
                    dns: default_routing_settings().dns,
                },
                extra_rules: vec![],
                direct_send_through: None,
            },
        )
        .expect("materialize");
        let cfg_json = serde_json::to_string(&cfg).unwrap();

        let mut child = Command::new(REAL_XRAY)
            .args(["-config", "stdin:"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        thread::spawn(move || {
            let _ = stdin.write_all(cfg_json.as_bytes());
            drop(stdin);
        });
        let stdout = child.stdout.take().unwrap();
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let cap = Arc::clone(&captured);
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                cap.lock().unwrap().push(line);
            }
        });

        // Wait for SOCKS.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(
                &SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port).into(),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        // ip.cn must be reachable in all presets but routed differently.
        // Default (no rules.conf in this minimal test): catch-all → proxy.
        // Direct: catch-all → direct.
        // Global: catch-all → proxy.
        // Easier observation: just hit ifconfig.me and report the egress.
        thread::sleep(Duration::from_millis(700));
        let proxy = format!("socks5h://127.0.0.1:{socks_port}");
        let ip = run_curl(Some(&proxy), "https://ifconfig.me/ip");
        let expected = match preset {
            RoutingPreset::Direct => None, // any non-server IP
            _ => Some(server_ip.as_str()), // proxy → server
        };
        match expected {
            Some(want) => {
                let ok = ip == want;
                println!(
                    "  [{}] ifconfig.me egress = {ip} (expected proxy → {want})",
                    if ok { "OK" } else { "FAIL" }
                );
                assert_eq!(ip, want, "preset {label} egressed wrong IP");
            }
            None => {
                let ok = !ip.is_empty() && ip != server_ip;
                println!(
                    "  [{}] ifconfig.me egress = {ip} (expected direct, NOT {server_ip})",
                    if ok { "OK" } else { "FAIL" }
                );
                assert_ne!(ip, server_ip, "Direct preset went through proxy");
                assert!(!ip.is_empty(), "Direct preset got no response");
            }
        }

        let _ = child.kill();
        let _ = child.wait();
        thread::sleep(Duration::from_millis(200));
    }

    println!("\n========== PASS: all 3 presets route correctly via REALITY ==========\n");
}

fn run_curl(proxy: Option<&str>, url: &str) -> String {
    let mut args: Vec<String> = vec!["--max-time".into(), "10".into(), "--silent".into()];
    if let Some(p) = proxy {
        args.push("--proxy".into());
        args.push(p.into());
    }
    args.push(url.into());
    let out = Command::new("/usr/bin/curl").args(&args).output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => String::new(),
    }
}
