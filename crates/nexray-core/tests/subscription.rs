// Per DEVELOPMENT.md §11: `expect`/`unwrap` are allowed in tests.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod fixtures;

use base64::Engine;
use fixtures::*;
use nexray_core::{classify_subscription, summarize_skipped, Profile, SkipReason};

#[test]
fn classifies_mixed_plaintext_list() {
    let body = mixed_plain_sub();
    let r = classify_subscription(&body);
    assert_eq!(r.accepted.len(), 3);
    let kinds: std::collections::BTreeSet<&str> = r
        .accepted
        .iter()
        .map(|p| match p {
            Profile::CdnWs(_) => "cdn-ws",
            Profile::Reality(_) => "reality",
            Profile::Trojan(_) => "trojan",
        })
        .collect();
    assert!(kinds.contains("cdn-ws"));
    assert!(kinds.contains("reality"));
    assert!(kinds.contains("trojan"));

    assert_eq!(r.skipped.len(), 9);
    let mut counts = std::collections::HashMap::new();
    for s in &r.skipped {
        *counts.entry(s.reason).or_insert(0_usize) += 1;
    }
    assert_eq!(counts.get(&SkipReason::VmessLegacy), Some(&1));
    assert_eq!(counts.get(&SkipReason::ShadowsocksLegacy), Some(&1));
    assert_eq!(counts.get(&SkipReason::TrojanGoLegacy), Some(&1));
    assert_eq!(counts.get(&SkipReason::TrojanWs), Some(&1));
    assert_eq!(counts.get(&SkipReason::RealityGrpc), Some(&1));
    assert_eq!(counts.get(&SkipReason::RealityWs), Some(&1));
    assert_eq!(counts.get(&SkipReason::VlessTlsDirect), Some(&1));
    assert_eq!(counts.get(&SkipReason::HttpUnsupported), Some(&1));
    assert_eq!(counts.get(&SkipReason::VlessKcp), Some(&1));
}

#[test]
fn decodes_base64_subscription() {
    let body = format!("{VALID_CDN_WS}\n{VALID_REALITY}\n");
    let wrapped = base64::engine::general_purpose::STANDARD.encode(&body);
    let r = classify_subscription(&wrapped);
    assert_eq!(r.accepted.len(), 2);
    assert_eq!(r.skipped.len(), 0);
}

#[test]
fn decodes_base64url_with_padding_stripped() {
    let body = format!("{VALID_CDN_WS}\n{VALID_REALITY}\n");
    let std = base64::engine::general_purpose::STANDARD.encode(&body);
    let urlsafe = std
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string();
    let r = classify_subscription(&urlsafe);
    assert_eq!(r.accepted.len(), 2);
}

#[test]
fn ignores_blank_and_comment_lines() {
    let body = format!("\n# comment\n{VALID_CDN_WS}\n\n");
    let r = classify_subscription(&body);
    assert_eq!(r.accepted.len(), 1);
    assert_eq!(r.skipped.len(), 0);
}

#[test]
fn does_not_panic_on_garbage() {
    let _ = classify_subscription(" junk");
}

#[test]
fn summary_matches_development_md_shape() {
    let r = classify_subscription(&mixed_plain_sub());
    let s = summarize_skipped(&r.skipped);
    assert!(s.starts_with("9 servers skipped: "), "got: {s}");
    assert!(s.contains("1 vmess (legacy)"));
    assert!(s.contains("1 shadowsocks (legacy)"));
    assert!(s.contains("1 trojan-go (legacy)"));
    assert!(s.contains("1 trojan+ws (unsupported)"));
}

#[test]
fn summary_empty_for_no_skipped() {
    assert_eq!(summarize_skipped(&[]), "");
}
