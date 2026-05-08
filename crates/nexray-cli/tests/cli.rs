//! CLI integration tests. Spawns the built `nexray-cli` binary and asserts
//! against stdout/stderr/exit-code.
//!
//! Per DEVELOPMENT.md §11: `expect`/`unwrap` are allowed in tests.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn classify_mixed_file_prints_table_and_summary() {
    Command::cargo_bin("nexray-cli")
        .expect("binary built")
        .arg("classify")
        .arg(fixture("mixed.txt"))
        .assert()
        .success()
        .stdout(predicate::str::contains("4 servers accepted"))
        .stdout(predicate::str::contains("9 servers skipped:"))
        .stdout(predicate::str::contains("vmess+ws (unsupported)"))
        .stdout(predicate::str::contains("trojan-go (legacy)"))
        .stdout(predicate::str::contains("trojan+ws (unsupported)"))
        .stdout(predicate::str::contains(
            "reality+grpc (invalid combination)",
        ))
        .stdout(predicate::str::contains(
            "vless+tls direct (use reality instead)",
        ));
}

#[test]
fn classify_json_emits_machine_readable_output() {
    let out = Command::cargo_bin("nexray-cli")
        .expect("binary built")
        .arg("classify")
        .arg(fixture("mixed.txt"))
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let s = String::from_utf8(out).expect("utf-8");
    let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
    assert_eq!(v["accepted"].as_array().expect("array").len(), 4);
    assert_eq!(v["skipped"].as_array().expect("array").len(), 9);

    let kinds: std::collections::BTreeSet<String> = v["accepted"]
        .as_array()
        .expect("array")
        .iter()
        .map(|p| p["kind"].as_str().expect("str").to_string())
        .collect();
    assert!(kinds.contains("cdn-ws"));
    assert!(kinds.contains("reality"));
    assert!(kinds.contains("trojan"));
    assert!(kinds.contains("vmess"));
}

#[test]
fn classify_rejects_http_url() {
    Command::cargo_bin("nexray-cli")
        .expect("binary built")
        .arg("classify")
        .arg("http://example.com")
        .assert()
        .failure()
        .stderr(predicate::str::contains("subscription URL must be HTTPS"));
}

#[test]
fn classify_missing_file_fails() {
    Command::cargo_bin("nexray-cli")
        .expect("binary built")
        .arg("classify")
        .arg("/this/does/not/exist.txt")
        .assert()
        .failure()
        .stderr(predicate::str::contains("could not read file"));
}

#[test]
fn classify_reads_stdin_with_dash() {
    use std::io::Write;
    let body = "vless://550e8400-e29b-41d4-a716-446655440000@1.2.3.4:443\
?type=ws&security=tls&host=h&path=/&sni=h&fp=chrome&encryption=none#a\n";

    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_nexray-cli"));
    cmd.arg("classify").arg("-").arg("--json");
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(body.as_bytes())
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success(), "status: {:?}", out.status);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["accepted"].as_array().expect("array").len(), 1);
}
