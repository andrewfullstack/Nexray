// Per DEVELOPMENT.md §11: `expect`/`unwrap` are allowed in tests.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod fixtures;

use fixtures::*;
use nexray_core::{decode_share_link, encode_share_link, DecodeResult, Profile, SkipReason};

fn expect_ok(raw: &str) -> Profile {
    match decode_share_link(raw) {
        DecodeResult::Ok { profile } => profile,
        DecodeResult::Err { reason, .. } => panic!("expected ok, got {reason}"),
    }
}

fn expect_err(raw: &str) -> SkipReason {
    match decode_share_link(raw) {
        DecodeResult::Ok { .. } => panic!("expected err, got ok for: {raw}"),
        DecodeResult::Err { reason, .. } => reason,
    }
}

#[test]
fn accepts_clean_cdn_ws() {
    let Profile::CdnWs(p) = expect_ok(VALID_CDN_WS) else {
        panic!("expected cdn-ws variant");
    };
    assert_eq!(p.address, "104.16.0.1");
    assert_eq!(p.port, 443);
    assert_eq!(p.host, "cdn.example.com");
    assert_eq!(p.path, "/?ed=2560");
    assert_eq!(p.sni, "cdn.example.com");
    assert_eq!(p.uuid, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(p.alpn.len(), 2);
    assert_eq!(p.remark.as_deref(), Some("CDN-Edge"));
}

#[test]
fn accepts_clean_reality() {
    let Profile::Reality(p) = expect_ok(VALID_REALITY) else {
        panic!("expected reality variant");
    };
    assert_eq!(p.address, "198.51.100.7");
    assert_eq!(p.port, 443);
    assert_eq!(p.sni, "www.microsoft.com");
    assert_eq!(p.public_key.len(), 43);
    assert_eq!(p.short_id, "abcd1234");
    assert_eq!(p.flow, "xtls-rprx-vision");
    assert_eq!(p.spider_x, "/");
    assert_eq!(p.remark.as_deref(), Some("Reality-VPS"));
}

#[test]
fn accepts_clean_trojan() {
    let Profile::Trojan(p) = expect_ok(VALID_TROJAN) else {
        panic!("expected trojan variant");
    };
    assert_eq!(p.address, "198.51.100.42");
    assert_eq!(p.port, 443);
    assert_eq!(p.password, "secret-pwd");
    assert_eq!(p.sni, "trojan.example.com");
    assert_eq!(p.alpn.len(), 2);
    assert_eq!(p.remark.as_deref(), Some("Trojan-VPS"));
}

#[test]
fn rejects_trojan_with_allow_insecure() {
    let raw = "trojan://pwd@1.2.3.4:443?type=tcp&sni=x.example.com&allowInsecure=1";
    assert_eq!(expect_err(raw), SkipReason::Malformed);
}

#[test]
fn rejects_legacy_and_invalid_combinations() {
    let cases: &[(&str, SkipReason)] = &[
        (VMESS_LINK, SkipReason::VmessLegacy),
        (SS_LINK, SkipReason::ShadowsocksLegacy),
        (SSR_LINK, SkipReason::ShadowsocksLegacy),
        (TROJAN_GO_LINK, SkipReason::TrojanGoLegacy),
        (TROJAN_WS_LINK, SkipReason::TrojanWs),
        (HTTP_LINK, SkipReason::HttpUnsupported),
        (SOCKS_LINK, SkipReason::SocksUnsupported),
        (REALITY_WS, SkipReason::RealityWs),
        (REALITY_GRPC, SkipReason::RealityGrpc),
        (VLESS_TLS_DIRECT, SkipReason::VlessTlsDirect),
        (VLESS_KCP, SkipReason::VlessKcp),
        (MALFORMED_NO_UUID, SkipReason::Malformed),
        (MALFORMED_BAD_FP, SkipReason::Malformed),
        (REALITY_BAD_PBK, SkipReason::Malformed),
    ];
    for (link, expected) in cases {
        assert_eq!(expect_err(link), *expected, "for input: {link}");
    }
}

#[test]
fn does_not_panic_on_garbage() {
    for s in ["", "   ", " ", "://", "vless://"] {
        let _ = decode_share_link(s);
    }
}

#[test]
fn cdn_ws_round_trips() {
    let original = expect_ok(VALID_CDN_WS);
    let re = expect_ok(&encode_share_link(&original));
    assert_eq!(format!("{:?}", original), format!("{:?}", re));
}

#[test]
fn reality_round_trips() {
    let original = expect_ok(VALID_REALITY);
    let re = expect_ok(&encode_share_link(&original));
    assert_eq!(format!("{:?}", original), format!("{:?}", re));
}

#[test]
fn trojan_round_trips() {
    let original = expect_ok(VALID_TROJAN);
    let encoded = encode_share_link(&original);
    assert!(
        encoded.starts_with("trojan://"),
        "expected trojan:// scheme, got {encoded}"
    );
    let re = expect_ok(&encoded);
    assert_eq!(format!("{:?}", original), format!("{:?}", re));
}
