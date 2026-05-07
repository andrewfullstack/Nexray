//! Routing-preset smoke test against real xray-core.
//!
//! For each of the 3 presets (Default / Direct / Global) we:
//!   1. Materialize the config with loglevel=info so xray prints
//!      `taking detour [tag]` lines.
//!   2. Spawn the real xray binary.
//!   3. Curl 3 destinations through the SOCKS inbound:
//!         - www.baidu.com  (geosite:cn)
//!         - ifconfig.me    (foreign)
//!         - googleads.g.doubleclick.net (geosite:category-ads-all)
//!   4. Grep xray stderr for `taking detour [direct|proxy|block]`
//!      and assert the destination matches the preset's expected behaviour.
//!
//! Ignored by default — run explicitly:
//!   cargo test -p nexray --test repro_routing -- --ignored --nocapture
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nexray_core::rules_conf;
use nexray_core::xray_config::{default_routing_settings, materialize, XrayConfigOptions};
use nexray_core::{
    decode_share_link, DecodeResult, Profile, RoutingPreset, RoutingSettings,
};

const REAL_XRAY: &str =
    "/Users/yangqi/Documents/github/nexray/src-tauri/binaries/Xray-macos-arm64-v8a/xray";

fn pick_loopback_port() -> u16 {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Live tests in this file all need a real CDN-WS proxy server. The
/// VLESS UUID gates the upstream so we don't ship one in source — set
/// `NEXRAY_TEST_VLESS_URL` to your own `vless://` share link before
/// running anything in this file with `--ignored`.
fn fixture_profile() -> Profile {
    let url = std::env::var("NEXRAY_TEST_VLESS_URL").unwrap_or_else(|_| {
        panic!(
            "set NEXRAY_TEST_VLESS_URL to your own VLESS+WS+TLS share link \
             (vless://uuid@host:443?type=ws&...) before running this test"
        )
    });
    match decode_share_link(&url) {
        DecodeResult::Ok { profile } => profile,
        DecodeResult::Err { reason, .. } => {
            panic!("NEXRAY_TEST_VLESS_URL did not parse: {reason:?}")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Direct,
    Proxy,
    Block,
}

impl Tag {
    fn parse(s: &str) -> Option<Tag> {
        match s {
            "direct" => Some(Tag::Direct),
            "proxy" => Some(Tag::Proxy),
            "block" => Some(Tag::Block),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct PresetExpect {
    preset: RoutingPreset,
    label: &'static str,
    /// (URL, expected outbound for routing decision)
    targets: Vec<(&'static str, Tag)>,
}

fn expectations() -> Vec<PresetExpect> {
    // Three URLs that exercise the divergent paths between presets.
    // - baidu.com is in geosite:cn → direct in Default
    // - ifconfig.me is foreign → proxy in Default
    // - googleads.g.doubleclick.net matches geosite:category-ads-all → block always
    vec![
        PresetExpect {
            preset: RoutingPreset::Default,
            label: "default",
            targets: vec![
                ("https://www.baidu.com", Tag::Direct),
                ("https://ifconfig.me", Tag::Proxy),
                ("https://googleads.g.doubleclick.net", Tag::Block),
            ],
        },
        PresetExpect {
            preset: RoutingPreset::Direct,
            label: "direct",
            targets: vec![
                ("https://www.baidu.com", Tag::Direct),
                ("https://ifconfig.me", Tag::Direct),
                ("https://googleads.g.doubleclick.net", Tag::Block),
            ],
        },
        PresetExpect {
            preset: RoutingPreset::Global,
            label: "global",
            targets: vec![
                ("https://www.baidu.com", Tag::Proxy),
                ("https://ifconfig.me", Tag::Proxy),
                ("https://googleads.g.doubleclick.net", Tag::Block),
            ],
        },
    ]
}

#[test]
#[ignore]
fn routing_presets_route_as_expected() {
    println!("\n========== nexray routing-preset smoke test ==========\n");

    let xray = PathBuf::from(REAL_XRAY);
    assert!(xray.exists(), "real xray missing at {}", xray.display());

    let mut all_ok = true;
    let mut summary: Vec<String> = vec![];

    for exp in expectations() {
        println!("\n--- preset: {} ---", exp.label);
        let socks_port = pick_loopback_port();
        let cfg = materialize(
            &fixture_profile(),
            &XrayConfigOptions {
                socks_port,
                stats_port: None,
                log_level: "info",
                routing: RoutingSettings {
                    preset: exp.preset,
                    custom_rules: vec![],
                    dns: default_routing_settings().dns,
                },
                extra_rules: vec![],
                direct_send_through: None,
            },
        )
        .expect("materialize");
        let cfg_json = serde_json::to_string(&cfg).expect("serialize");

        let mut child = Command::new(&xray)
            .args(["-config", "stdin:"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn xray");

        let mut stdin = child.stdin.take().expect("stdin");
        thread::spawn(move || {
            let _ = stdin.write_all(cfg_json.as_bytes());
            drop(stdin);
        });

        // xray writes ALL logs (info, warn, access) to stdout. stderr is empty.
        let stdout = child.stdout.take().expect("stdout");
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = Arc::clone(&captured);
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                captured_clone.lock().unwrap().push(line);
            }
        });
        // Drain stderr to avoid pipe-full deadlock (it's empty in practice but keep safe).
        let stderr = child.stderr.take().expect("stderr");
        thread::spawn(move || {
            for _ in BufReader::new(stderr).lines().map_while(Result::ok) {}
        });

        // Wait for SOCKS port to come up.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut ready = false;
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(
                &SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port).into(),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                ready = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        if !ready {
            eprintln!("xray failed to bind SOCKS {socks_port}; skipping this preset");
            let _ = child.kill();
            all_ok = false;
            summary.push(format!("[{}] FAIL: xray never bound SOCKS port", exp.label));
            continue;
        }

        for (url, expect_tag) in &exp.targets {
            // Find the host portion for log-correlation.
            let host = url
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or(url);

            // Snapshot pre-curl log line count so we can scan ONLY new lines.
            let pre_count = captured.lock().unwrap().len();

            let curl = Command::new("/usr/bin/curl")
                .args([
                    "--max-time",
                    "8",
                    "--silent",
                    "--output",
                    "/dev/null",
                    "--proxy",
                    &format!("socks5h://127.0.0.1:{socks_port}"),
                    url,
                ])
                .output();
            let exit_status = curl.as_ref().map(|o| o.status).ok();

            // Give xray 200ms to flush the routing log line.
            thread::sleep(Duration::from_millis(200));

            // Scan new stderr lines for `taking detour [tag] for [tcp:host:...]`.
            let lines = captured.lock().unwrap().clone();
            let new_lines = &lines[pre_count..];
            let mut detour: Option<Tag> = None;
            for line in new_lines {
                let Some(idx) = line.find("taking detour [") else {
                    continue;
                };
                if !line.contains(host) {
                    continue;
                }
                // line: "... app/dispatcher: taking detour [direct] for [tcp:host:443]"
                let after = &line[idx + "taking detour [".len()..];
                if let Some(end) = after.find(']') {
                    if let Some(t) = Tag::parse(&after[..end]) {
                        detour = Some(t);
                        break;
                    }
                }
            }

            let actual = match detour {
                Some(t) => format!("{:?}", t),
                None => "?".into(),
            };
            let ok = detour == Some(*expect_tag);
            if !ok {
                all_ok = false;
            }
            println!(
                "  [{}] {} → expected {:?}, got {} (curl exit: {:?})",
                if ok { "OK" } else { "FAIL" },
                host,
                expect_tag,
                actual,
                exit_status
            );
            summary.push(format!(
                "[{}] {}: expected {:?}, got {} {}",
                exp.label,
                host,
                expect_tag,
                actual,
                if ok { "OK" } else { "FAIL" }
            ));

            if !ok {
                // Dump the relevant log fragment to help diagnose.
                println!("    --- xray log fragment ---");
                for line in new_lines.iter().take(40) {
                    if line.contains(host) || line.contains("taking detour") {
                        println!("    {}", line);
                    }
                }
            }
        }

        let _ = child.kill();
        let _ = child.wait();
        thread::sleep(Duration::from_millis(200));
    }

    println!("\n========== summary ==========");
    for line in &summary {
        println!("{line}");
    }
    println!();
    assert!(all_ok, "one or more routing presets misbehaved — see above");
}

// ---------------------------------------------------------------------------
// Kill-switch verification with the user's actual rules.conf
//
// The bug: with `DOMAIN-SUFFIX,cn,DIRECT` and `FINAL,PROXY` in rules.conf
// (Shadowrocket-style), Global preset still leaked .cn domains direct
// (so ip.cn returned the home IP) and the ads-block never fired
// (FINAL,PROXY hit before the preset's ad rule).
//
// This test loads the user's real rules.conf, materializes a Global-mode
// config, spawns xray, and asserts:
//   * ip.cn is routed through the proxy (`taking detour [proxy]`)
//   * an ad domain is BLOCKED (`taking detour [block]`)
//   * baidu.com (which has its own DOMAIN-SUFFIX,baidu.com,DIRECT) is
//     also forced to proxy by kill-switch — sanity check.
// ---------------------------------------------------------------------------

const RULES_CONF: &str = "/Users/yangqi/Library/Application Support/dev.nexray.app/rules.conf";
const ROUTING_JSON: &str = "/Users/yangqi/Library/Application Support/dev.nexray.app/routing.json";

/// Reqwest with a SOCKS5h proxy must route through xray, NOT the default
/// route. Symptom of the original bug: chained `.no_proxy()` after
/// `.proxy(p)` cleared the explicit proxy, so reqwest fell back to the
/// system default and the in-app egress check returned the user's home
/// IP. This test catches that regression by comparing direct vs proxied
/// `ifconfig.me/ip` results — they MUST differ when xray is healthy.
#[test]
#[ignore]
fn egress_check_actually_proxies_through_xray() {
    println!("\n========== egress_check goes through xray, not direct ==========\n");
    let xray = PathBuf::from(REAL_XRAY);
    assert!(xray.exists());

    // Spawn xray (default preset, no rules.conf — keeps test self-contained).
    let socks_port = pick_loopback_port();
    let cfg = materialize(
        &fixture_profile(),
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
    let cfg_json = serde_json::to_string(&cfg).unwrap();

    let mut child = Command::new(&xray)
        .args(["-config", "stdin:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    thread::spawn(move || {
        let _ = stdin.write_all(cfg_json.as_bytes());
        drop(stdin);
    });

    // Wait for SOCKS bind.
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

    // Direct curl — what the user's home IP looks like, as a control.
    let direct_out = Command::new("/usr/bin/curl")
        .args(["--max-time", "8", "--silent", "https://ifconfig.me/ip"])
        .output()
        .unwrap();
    let direct_ip = String::from_utf8_lossy(&direct_out.stdout).trim().to_string();
    println!("  direct egress: {}", direct_ip);

    // Run reqwest with the same setup the egress_check command uses.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let proxied_ip = runtime.block_on(async {
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}"))
            .expect("proxy parse");
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(8))
            .build()
            .expect("client");
        let resp = client.get("https://ifconfig.me/ip").send().await.expect("send");
        assert!(resp.status().is_success(), "got {}", resp.status());
        resp.text().await.expect("body").trim().to_string()
    });
    println!("  proxied egress: {}", proxied_ip);

    let _ = child.kill();
    let _ = child.wait();

    assert!(!proxied_ip.is_empty(), "proxied egress should not be empty");
    assert!(!direct_ip.is_empty(), "direct egress should not be empty");
    assert_ne!(
        proxied_ip, direct_ip,
        "proxied egress matched direct — reqwest is bypassing the SOCKS proxy"
    );
}

#[test]
#[ignore]
fn diagnose_running_app_default_preset_cn_route() {
    println!("\n========== diagnose: default preset + real rules.conf — does ip.cn route DIRECT? ==========\n");

    let xray = PathBuf::from(REAL_XRAY);
    assert!(xray.exists());
    let rules_text = std::fs::read_to_string(RULES_CONF).unwrap();
    let conf = rules_conf::parse(&rules_text);
    let translated = rules_conf::translate(&conf);
    println!(
        "rules.conf: {} translated, {} skipped",
        translated.rules.len(),
        translated.skipped.len()
    );

    let routing_raw = std::fs::read_to_string(ROUTING_JSON).unwrap();
    let routing_outer: serde_json::Value = serde_json::from_str(&routing_raw).unwrap();
    let saved: nexray_core::RoutingSettings =
        serde_json::from_value(routing_outer["routing"].clone()).unwrap();
    println!("saved preset: {:?}", saved.preset);

    let socks_port = pick_loopback_port();
    let cfg = materialize(
        &fixture_profile(),
        &XrayConfigOptions {
            socks_port,
            stats_port: None,
            log_level: "info",
            routing: saved,
            extra_rules: translated.rules,
            direct_send_through: Some("192.168.4.29".into()),
        },
    )
    .expect("materialize");
    let cfg_json = serde_json::to_string(&cfg).unwrap();
    println!("config size: {} bytes", cfg_json.len());

    let mut child = Command::new(&xray)
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
    thread::spawn(move || {
        for _ in BufReader::new(stderr).lines().map_while(Result::ok) {}
    });

    // Wait for SOCKS bind.
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

    for url in &["https://ip.cn", "https://www.baidu.com", "https://ifconfig.me"] {
        let host = url
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap();
        let pre = captured.lock().unwrap().len();
        let out = Command::new("/usr/bin/curl")
            .args([
                "--max-time",
                "8",
                "--silent",
                "--output",
                "/dev/null",
                "-w",
                "code=%{http_code}/exit=%{exitcode}",
                "--proxy",
                &format!("socks5h://127.0.0.1:{socks_port}"),
                url,
            ])
            .output()
            .unwrap();
        thread::sleep(Duration::from_millis(200));

        let lines = captured.lock().unwrap().clone();
        let new_lines = &lines[pre..];
        let mut detour: Option<Tag> = None;
        for line in new_lines {
            let Some(idx) = line.find("taking detour [") else { continue };
            if !line.contains(host) { continue; }
            let after = &line[idx + "taking detour [".len()..];
            if let Some(end) = after.find(']') {
                if let Some(t) = Tag::parse(&after[..end]) {
                    detour = Some(t);
                    break;
                }
            }
        }
        println!(
            "  {} curl={} detour={:?}",
            host,
            String::from_utf8_lossy(&out.stdout).trim(),
            detour
        );
        // Print only routing-relevant log lines.
        for line in new_lines.iter().take(50) {
            if line.contains(host) && (line.contains("detour") || line.contains("freedom") || line.contains("dialing") || line.contains("DNS")) {
                println!("    {line}");
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[ignore]
fn global_kill_switch_overrides_rules_conf_cn_direct() {
    println!("\n========== Global kill-switch with real rules.conf ==========\n");

    let xray = PathBuf::from(REAL_XRAY);
    assert!(xray.exists(), "real xray missing at {}", xray.display());

    let rules_text = std::fs::read_to_string(RULES_CONF)
        .unwrap_or_else(|e| panic!("read rules.conf: {e}"));
    let conf = rules_conf::parse(&rules_text);
    let translated = rules_conf::translate(&conf);
    let extra_rules = translated.rules;
    println!(
        "rules.conf: {} translated rules, {} skipped (incl. FINAL drop)",
        extra_rules.len(),
        translated.skipped.len()
    );

    let socks_port = pick_loopback_port();
    let cfg = materialize(
        &fixture_profile(),
        &XrayConfigOptions {
            socks_port,
            stats_port: None,
            log_level: "info",
            routing: RoutingSettings {
                preset: RoutingPreset::Global,
                custom_rules: vec![],
                dns: default_routing_settings().dns,
            },
            extra_rules,
            direct_send_through: None,
        },
    )
    .expect("materialize");
    let cfg_json = serde_json::to_string(&cfg).expect("serialize");

    let mut child = Command::new(&xray)
        .args(["-config", "stdin:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn xray");

    let mut stdin = child.stdin.take().expect("stdin");
    thread::spawn(move || {
        let _ = stdin.write_all(cfg_json.as_bytes());
        drop(stdin);
    });

    let stdout = child.stdout.take().expect("stdout");
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = Arc::clone(&captured);
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            captured_clone.lock().unwrap().push(line);
        }
    });
    let stderr = child.stderr.take().expect("stderr");
    thread::spawn(move || {
        for _ in BufReader::new(stderr).lines().map_while(Result::ok) {}
    });

    // Wait for SOCKS port to come up.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ready = false;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port).into(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "xray failed to bind SOCKS {socks_port}");

    let targets: Vec<(&'static str, Tag)> = vec![
        ("https://ip.cn", Tag::Proxy),
        ("https://www.baidu.com", Tag::Proxy),
        ("https://googleads.g.doubleclick.net", Tag::Block),
    ];

    let mut all_ok = true;
    for (url, expect) in &targets {
        let host = url
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or(url);
        let pre = captured.lock().unwrap().len();
        let _ = Command::new("/usr/bin/curl")
            .args([
                "--max-time",
                "8",
                "--silent",
                "--output",
                "/dev/null",
                "--proxy",
                &format!("socks5h://127.0.0.1:{socks_port}"),
                url,
            ])
            .output();
        thread::sleep(Duration::from_millis(200));

        let lines = captured.lock().unwrap().clone();
        let new_lines = &lines[pre..];
        let mut detour: Option<Tag> = None;
        for line in new_lines {
            let Some(idx) = line.find("taking detour [") else { continue };
            if !line.contains(host) { continue; }
            let after = &line[idx + "taking detour [".len()..];
            if let Some(end) = after.find(']') {
                if let Some(t) = Tag::parse(&after[..end]) {
                    detour = Some(t);
                    break;
                }
            }
        }
        let ok = detour == Some(*expect);
        if !ok { all_ok = false; }
        println!(
            "  [{}] {} → expected {:?}, got {:?}",
            if ok { "OK" } else { "FAIL" },
            host,
            expect,
            detour
        );
    }

    let _ = child.kill();
    let _ = child.wait();
    assert!(all_ok, "kill-switch did not work as expected");
}
