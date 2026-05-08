// Per DEVELOPMENT.md §11: `expect`/`unwrap` are allowed in tests.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod fixtures;

use fixtures::{VALID_CDN_WS, VALID_REALITY, VALID_TROJAN, VALID_VMESS};
use nexray_core::xray_config::{
    default_routing_settings, materialize, MaterializeError, XrayConfigOptions,
};
use nexray_core::{
    decode_share_link, CustomRule, DecodeResult, DnsConfig, Profile, RoutingDestination,
    RoutingMatcherType, RoutingPreset, RoutingSettings,
};

fn parse(raw: &str) -> Profile {
    match decode_share_link(raw) {
        DecodeResult::Ok { profile } => profile,
        DecodeResult::Err { reason, .. } => panic!("expected ok, got {reason}"),
    }
}

fn cdn_ws_config(opts: XrayConfigOptions) -> serde_json::Value {
    materialize(&parse(VALID_CDN_WS), &opts).expect("materialize")
}

fn reality_config(opts: XrayConfigOptions) -> serde_json::Value {
    materialize(&parse(VALID_REALITY), &opts).expect("materialize")
}

fn trojan_config(opts: XrayConfigOptions) -> serde_json::Value {
    materialize(&parse(VALID_TROJAN), &opts).expect("materialize")
}

fn vmess_config(opts: XrayConfigOptions) -> serde_json::Value {
    materialize(&parse(VALID_VMESS), &opts).expect("materialize")
}

#[test]
fn cdn_ws_outbound_matches_development_md_shape() {
    let cfg = cdn_ws_config(XrayConfigOptions::default());
    let outbound = &cfg["outbounds"][0];
    assert_eq!(outbound["protocol"], "vless");
    assert_eq!(outbound["tag"], "proxy");
    assert_eq!(outbound["streamSettings"]["network"], "ws");
    assert_eq!(outbound["streamSettings"]["security"], "tls");
    assert_eq!(
        outbound["streamSettings"]["tlsSettings"]["fingerprint"],
        "chrome"
    );
    // §12 rule: never trust allowInsecure from inputs; materializer always emits false.
    assert_eq!(
        outbound["streamSettings"]["tlsSettings"]["allowInsecure"],
        false
    );
    assert_eq!(
        outbound["streamSettings"]["wsSettings"]["headers"]["Host"],
        "cdn.example.com"
    );
    assert_eq!(
        outbound["streamSettings"]["wsSettings"]["path"],
        "/?ed=2560"
    );
}

#[test]
fn reality_outbound_matches_development_md_shape() {
    let cfg = reality_config(XrayConfigOptions::default());
    let outbound = &cfg["outbounds"][0];
    assert_eq!(outbound["protocol"], "vless");
    assert_eq!(
        outbound["settings"]["vnext"][0]["users"][0]["flow"],
        "xtls-rprx-vision"
    );
    assert_eq!(outbound["streamSettings"]["network"], "tcp");
    assert_eq!(outbound["streamSettings"]["security"], "reality");
    assert_eq!(
        outbound["streamSettings"]["realitySettings"]["serverName"],
        "www.microsoft.com"
    );
    assert_eq!(
        outbound["streamSettings"]["realitySettings"]["shortId"],
        "abcd1234"
    );
}

#[test]
fn socks_inbound_is_localhost_only() {
    let cfg = cdn_ws_config(XrayConfigOptions {
        socks_port: 1234,
        ..Default::default()
    });
    let inbound = &cfg["inbounds"][0];
    assert_eq!(inbound["tag"], "socks-in");
    assert_eq!(inbound["listen"], "127.0.0.1");
    assert_eq!(inbound["port"], 1234);
    assert_eq!(inbound["protocol"], "socks");
    assert_eq!(inbound["settings"]["udp"], true);
}

#[test]
fn default_routing_rules_match_development_md() {
    let cfg = cdn_ws_config(XrayConfigOptions::default());
    let rules = cfg["routing"]["rules"].as_array().expect("rules array");
    let texts: Vec<String> = rules.iter().map(|r| r.to_string()).collect();
    let joined = texts.join("\n");

    assert!(joined.contains("geoip:private"));
    assert!(joined.contains("\"geosite:category-ads-all\""));
    assert!(joined.contains("\"geosite:cn\""));
    assert!(joined.contains("\"geoip:cn\""));
    assert!(joined.contains("\"block\""));
    assert!(joined.contains("\"direct\""));
    assert!(joined.contains("\"proxy\""));
}

#[test]
fn dns_uses_alidns_for_cn_and_doh_for_proxy() {
    let cfg = cdn_ws_config(XrayConfigOptions::default());
    let dns = cfg["dns"].to_string();
    assert!(dns.contains("https://1.1.1.1/dns-query"));
    assert!(dns.contains("223.5.5.5"));
    assert!(dns.contains("geosite:cn"));
    assert!(dns.contains("geoip:cn"));
    // §6.1 fallback: the proxy resolver must also appear as a string-form
    // catch-all so `.cn` domains hosted on foreign IPs (rejected by the
    // expectIPs filter) still resolve.
    let servers = cfg["dns"]["servers"].as_array().expect("servers array");
    let has_string_fallback = servers
        .iter()
        .any(|s| s.is_string() && s.as_str() == Some("https://1.1.1.1/dns-query"));
    assert!(
        has_string_fallback,
        "expected a string-form fallback DoH server for unfiltered queries; got {servers:?}"
    );
}

#[test]
fn stats_disabled_by_default() {
    let cfg = cdn_ws_config(XrayConfigOptions::default());
    assert!(cfg.get("api").is_none());
    assert!(cfg.get("stats").is_none());
    assert!(cfg.get("policy").is_none());
    let inbounds = cfg["inbounds"].as_array().expect("array");
    assert_eq!(inbounds.len(), 1);
}

#[test]
fn stats_enabled_adds_api_inbound_and_routing_rule() {
    let cfg = cdn_ws_config(XrayConfigOptions {
        socks_port: 10808,
        stats_port: Some(58080),
        ..Default::default()
    });

    assert_eq!(cfg["api"]["tag"], "api");
    assert_eq!(cfg["api"]["services"][0], "StatsService");
    assert_eq!(cfg["stats"], serde_json::json!({}));

    let inbounds = cfg["inbounds"].as_array().expect("array");
    assert_eq!(inbounds.len(), 2);
    let api_in = inbounds
        .iter()
        .find(|i| i["tag"] == "api-in")
        .expect("api-in");
    assert_eq!(api_in["port"], 58080);
    assert_eq!(api_in["listen"], "127.0.0.1");

    let outbounds = cfg["outbounds"].as_array().expect("array");
    assert!(outbounds.iter().any(|o| o["tag"] == "api"));

    // First routing rule must send api-in to api outbound (highest priority).
    let first_rule = &cfg["routing"]["rules"][0];
    assert_eq!(first_rule["inboundTag"][0], "api-in");
    assert_eq!(first_rule["outboundTag"], "api");
}

#[test]
fn rejects_empty_mandatory_field() {
    let mut cdn_ws = match parse(VALID_CDN_WS) {
        Profile::CdnWs(p) => p,
        _ => panic!("expected cdn-ws"),
    };
    cdn_ws.host = String::new();
    let err = materialize(&Profile::CdnWs(cdn_ws), &XrayConfigOptions::default())
        .expect_err("should reject empty host");
    assert!(matches!(
        err,
        MaterializeError::InvalidField {
            kind: "cdn-ws",
            field: "host"
        }
    ));
}

#[test]
fn direct_preset_routes_everything_direct_with_ads_blocked() {
    let cfg = materialize(
        &parse(VALID_CDN_WS),
        &XrayConfigOptions {
            routing: RoutingSettings {
                preset: RoutingPreset::Direct,
                custom_rules: vec![],
                dns: default_routing_settings().dns,
            },
            ..Default::default()
        },
    )
    .expect("materialize");
    let rules = cfg["routing"]["rules"].as_array().expect("rules array");
    let texts: Vec<String> = rules.iter().map(|r| r.to_string()).collect();
    let joined = texts.join("\n");
    assert!(joined.contains("\"block\""));
    // Direct preset must not have a `geosite:cn` rule (everything is direct
    // anyway).
    assert!(!joined.contains("\"geosite:cn\""));
    // The catch-all rule sends to `direct`, not `proxy`.
    let last = rules.last().expect("last");
    assert_eq!(last["outboundTag"], "direct");
}

#[test]
fn kill_switch_presets_drop_direct_and_proxy_extras_keep_block() {
    use serde_json::json;
    // Simulated extra_rules from a translated rules.conf — what
    // `connect`/`reload_sidecar_with_current_routing` passes to materialize.
    let extras = vec![
        json!({"type": "field", "domain": ["domain:cn"], "outboundTag": "direct"}),
        json!({"type": "field", "domain": ["full:foo.example"], "outboundTag": "proxy"}),
        json!({"type": "field", "domain": ["domain:ads.example"], "outboundTag": "block"}),
    ];
    for preset in [RoutingPreset::Direct, RoutingPreset::Global] {
        let cfg = materialize(
            &parse(VALID_CDN_WS),
            &XrayConfigOptions {
                routing: RoutingSettings {
                    preset,
                    custom_rules: vec![],
                    dns: default_routing_settings().dns,
                },
                extra_rules: extras.clone(),
                ..Default::default()
            },
        )
        .expect("materialize");
        let rules = cfg["routing"]["rules"].as_array().expect("rules array");
        let joined = rules
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        // The .cn-direct rule MUST NOT survive — that's the bug fix
        // (otherwise Global leaks the home IP for ip.cn).
        assert!(
            !joined.contains("domain:cn"),
            "{preset:?}: extras direct rule survived: {joined}"
        );
        assert!(
            !joined.contains("full:foo.example"),
            "{preset:?}: extras proxy rule survived"
        );
        // Block rule from rules.conf MUST survive so ad-filtering keeps
        // working in kill-switch modes.
        assert!(
            joined.contains("domain:ads.example"),
            "{preset:?}: extras block rule was dropped"
        );
    }
}

#[test]
fn default_preset_keeps_all_extras() {
    use serde_json::json;
    let extras = vec![
        json!({"type": "field", "domain": ["domain:cn"], "outboundTag": "direct"}),
        json!({"type": "field", "domain": ["full:foo.example"], "outboundTag": "proxy"}),
        json!({"type": "field", "domain": ["domain:ads.example"], "outboundTag": "block"}),
    ];
    let cfg = materialize(
        &parse(VALID_CDN_WS),
        &XrayConfigOptions {
            routing: RoutingSettings {
                preset: RoutingPreset::Default,
                custom_rules: vec![],
                dns: default_routing_settings().dns,
            },
            extra_rules: extras.clone(),
            ..Default::default()
        },
    )
    .expect("materialize");
    let joined = cfg["routing"]["rules"]
        .as_array()
        .expect("rules array")
        .iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(joined.contains("domain:cn"));
    assert!(joined.contains("full:foo.example"));
    assert!(joined.contains("domain:ads.example"));
}

#[test]
fn global_preset_routes_everything_proxy_except_private_and_ads() {
    let cfg = materialize(
        &parse(VALID_CDN_WS),
        &XrayConfigOptions {
            routing: RoutingSettings {
                preset: RoutingPreset::Global,
                custom_rules: vec![],
                dns: default_routing_settings().dns,
            },
            ..Default::default()
        },
    )
    .expect("materialize");
    let rules = cfg["routing"]["rules"].as_array().expect("rules array");
    let last = rules.last().expect("last");
    assert_eq!(last["outboundTag"], "proxy");
    let texts = rules
        .iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(texts.contains("\"geoip:private\""));
    assert!(!texts.contains("\"geosite:cn\""));
}

#[test]
fn custom_rules_are_prepended_first_match_wins() {
    let custom = CustomRule {
        id: "u1".into(),
        matcher_type: RoutingMatcherType::Domain,
        matcher: "geosite:youtube".into(),
        destination: RoutingDestination::Block,
        enabled: true,
    };
    let cfg = materialize(
        &parse(VALID_CDN_WS),
        &XrayConfigOptions {
            routing: RoutingSettings {
                preset: RoutingPreset::Default,
                custom_rules: vec![custom],
                dns: default_routing_settings().dns,
            },
            ..Default::default()
        },
    )
    .expect("materialize");
    let rules = cfg["routing"]["rules"].as_array().expect("rules array");
    // The user rule must be first (Xray first-match-wins).
    let first = &rules[0];
    assert_eq!(first["domain"][0], "geosite:youtube");
    assert_eq!(first["outboundTag"], "block");
}

#[test]
fn disabled_custom_rules_are_skipped() {
    let custom = CustomRule {
        id: "u1".into(),
        matcher_type: RoutingMatcherType::Domain,
        matcher: "geosite:youtube".into(),
        destination: RoutingDestination::Block,
        enabled: false,
    };
    let cfg = materialize(
        &parse(VALID_CDN_WS),
        &XrayConfigOptions {
            routing: RoutingSettings {
                preset: RoutingPreset::Default,
                custom_rules: vec![custom],
                dns: default_routing_settings().dns,
            },
            ..Default::default()
        },
    )
    .expect("materialize");
    let rules = cfg["routing"]["rules"].as_array().expect("rules array");
    let texts = rules
        .iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    // No user rule visible.
    assert!(!texts.contains("geosite:youtube"));
}

#[test]
fn dns_overrides_propagate_to_config() {
    let cfg = materialize(
        &parse(VALID_CDN_WS),
        &XrayConfigOptions {
            routing: RoutingSettings {
                preset: RoutingPreset::Default,
                custom_rules: vec![],
                dns: DnsConfig {
                    domestic_resolver: "114.114.114.114".into(),
                    proxy_resolver: "tls://9.9.9.9".into(),
                },
            },
            ..Default::default()
        },
    )
    .expect("materialize");
    let dns = cfg["dns"].to_string();
    assert!(dns.contains("114.114.114.114"));
    assert!(dns.contains("tls://9.9.9.9"));
    assert!(!dns.contains("https://1.1.1.1"));
    assert!(!dns.contains("223.5.5.5"));
}

#[test]
fn trojan_outbound_matches_xray_shape() {
    let cfg = trojan_config(XrayConfigOptions::default());
    let outbound = &cfg["outbounds"][0];
    assert_eq!(outbound["protocol"], "trojan");
    assert_eq!(outbound["tag"], "proxy");
    let server = &outbound["settings"]["servers"][0];
    assert_eq!(server["address"], "198.51.100.42");
    assert_eq!(server["port"], 443);
    assert_eq!(server["password"], "secret-pwd");
    assert_eq!(outbound["streamSettings"]["network"], "tcp");
    assert_eq!(outbound["streamSettings"]["security"], "tls");
    assert_eq!(
        outbound["streamSettings"]["tlsSettings"]["serverName"],
        "trojan.example.com"
    );
    assert_eq!(
        outbound["streamSettings"]["tlsSettings"]["fingerprint"],
        "chrome"
    );
    // §12 rule: never trust allowInsecure from inputs; materializer always emits false.
    assert_eq!(
        outbound["streamSettings"]["tlsSettings"]["allowInsecure"],
        false
    );
}

#[test]
fn rejects_empty_trojan_password() {
    let mut trojan = match parse(VALID_TROJAN) {
        Profile::Trojan(p) => p,
        _ => panic!("expected trojan"),
    };
    trojan.password = String::new();
    let err = materialize(&Profile::Trojan(trojan), &XrayConfigOptions::default())
        .expect_err("should reject empty password");
    assert!(matches!(
        err,
        MaterializeError::InvalidField {
            kind: "trojan",
            field: "password"
        }
    ));
}

#[test]
fn vmess_outbound_matches_xray_shape() {
    let cfg = vmess_config(XrayConfigOptions::default());
    let outbound = &cfg["outbounds"][0];
    assert_eq!(outbound["protocol"], "vmess");
    assert_eq!(outbound["tag"], "proxy");
    let user = &outbound["settings"]["vnext"][0]["users"][0];
    assert_eq!(user["id"], "550e8400-e29b-41d4-a716-446655440042");
    assert_eq!(user["alterId"], 0);
    assert_eq!(user["security"], "auto");
    let vnext = &outbound["settings"]["vnext"][0];
    assert_eq!(vnext["address"], "198.51.100.77");
    assert_eq!(vnext["port"], 443);
    assert_eq!(outbound["streamSettings"]["network"], "tcp");
    assert_eq!(outbound["streamSettings"]["security"], "tls");
    assert_eq!(
        outbound["streamSettings"]["tlsSettings"]["serverName"],
        "vmess.example.com"
    );
    assert_eq!(
        outbound["streamSettings"]["tlsSettings"]["fingerprint"],
        "chrome"
    );
    // §12 rule: never trust allowInsecure from inputs; materializer always emits false.
    assert_eq!(
        outbound["streamSettings"]["tlsSettings"]["allowInsecure"],
        false
    );
}

#[test]
fn rejects_empty_vmess_uuid() {
    let mut vmess = match parse(VALID_VMESS) {
        Profile::Vmess(p) => p,
        _ => panic!("expected vmess"),
    };
    vmess.uuid = String::new();
    let err = materialize(&Profile::Vmess(vmess), &XrayConfigOptions::default())
        .expect_err("should reject empty uuid");
    assert!(matches!(
        err,
        MaterializeError::InvalidField {
            kind: "vmess",
            field: "uuid"
        }
    ));
}

#[test]
fn rejects_wrong_reality_flow() {
    let mut reality = match parse(VALID_REALITY) {
        Profile::Reality(p) => p,
        _ => panic!("expected reality"),
    };
    reality.flow = "xtls-rprx-direct".to_string();
    let err = materialize(&Profile::Reality(reality), &XrayConfigOptions::default())
        .expect_err("should reject non-vision flow");
    assert!(matches!(
        err,
        MaterializeError::InvalidField {
            kind: "reality",
            field: "flow"
        }
    ));
}
