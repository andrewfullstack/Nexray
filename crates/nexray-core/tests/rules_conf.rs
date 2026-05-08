// Per DEVELOPMENT.md §11: `expect`/`unwrap` are allowed in tests.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use nexray_core::rules_conf::{parse, render, translate, ParsedRule, RuleKind};
use nexray_core::RoutingDestination;

const SAMPLE: &str = "# Top of file\n[General]\nipv6 = true\n\n[Rule]\n# Block HTTP3/QUIC\n# AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP\nDOMAIN-SUFFIX,apple.com,DIRECT\nDOMAIN,copilot.microsoft.com,PROXY\nIP-ASN,132203,DIRECT,no-resolve\nIP-CIDR,10.0.0.0/8,DIRECT\nGEOIP,CN,DIRECT\nFINAL,PROXY\n";

#[test]
fn parses_known_rule_types() {
    let conf = parse(SAMPLE);
    let rules: Vec<&ParsedRule> = conf.rules().collect();
    assert_eq!(rules.len(), 7);

    // The "AND" combinator is commented out, so it's a disabled rule.
    assert!(!rules[0].enabled);
    assert!(matches!(rules[0].kind, RuleKind::Other { .. }));

    // DOMAIN-SUFFIX,apple.com,DIRECT
    assert!(rules[1].enabled);
    assert_eq!(rules[1].policy, RoutingDestination::Direct);
    assert!(matches!(rules[1].kind, RuleKind::DomainSuffix(ref v) if v == "apple.com"));

    // DOMAIN,copilot.microsoft.com,PROXY
    assert!(matches!(rules[2].kind, RuleKind::Domain(ref v) if v == "copilot.microsoft.com"));
    assert_eq!(rules[2].policy, RoutingDestination::Proxy);

    // IP-ASN,132203,DIRECT,no-resolve
    assert!(matches!(rules[3].kind, RuleKind::IpAsn(ref v) if v == "132203"));
    assert!(rules[3].no_resolve);

    // IP-CIDR + GEOIP + FINAL
    assert!(matches!(rules[4].kind, RuleKind::IpCidr(ref v) if v == "10.0.0.0/8"));
    assert!(matches!(rules[5].kind, RuleKind::Geoip(ref v) if v == "CN"));
    assert!(matches!(rules[6].kind, RuleKind::Final));
    assert_eq!(rules[6].policy, RoutingDestination::Proxy);
}

#[test]
fn round_trips_recognized_input() {
    let conf = parse(SAMPLE);
    let rendered = render(&conf);
    assert_eq!(rendered, SAMPLE);
}

#[test]
fn append_inserts_into_rule_section() {
    let mut conf = parse(SAMPLE);
    let new_rule = ParsedRule {
        kind: RuleKind::DomainSuffix("github.com".into()),
        policy: RoutingDestination::Proxy,
        no_resolve: false,
        enabled: true,
    };
    conf.append_rule(new_rule);
    let rendered = render(&conf);
    assert!(rendered.contains("DOMAIN-SUFFIX,github.com,PROXY"));
    // The new rule should appear before [Host] etc. — there's no other
    // section in SAMPLE so it lands after FINAL.
    let idx_final = rendered.find("FINAL,PROXY").expect("final");
    let idx_new = rendered
        .find("DOMAIN-SUFFIX,github.com,PROXY")
        .expect("new");
    assert!(idx_new > idx_final);
}

#[test]
fn toggle_enabled_round_trips() {
    let mut conf = parse(SAMPLE);
    // Rule 1 = DOMAIN-SUFFIX,apple.com,DIRECT (enabled).
    conf.set_rule_enabled(1, false);
    let rendered = render(&conf);
    assert!(rendered.contains("# DOMAIN-SUFFIX,apple.com,DIRECT"));
    let mut conf2 = parse(&rendered);
    let rules: Vec<&ParsedRule> = conf2.rules().collect();
    assert!(!rules[1].enabled);
    // Re-enable and confirm reverse direction.
    conf2.set_rule_enabled(1, true);
    let rendered2 = render(&conf2);
    assert!(rendered2.contains("DOMAIN-SUFFIX,apple.com,DIRECT"));
    assert!(!rendered2.contains("# DOMAIN-SUFFIX,apple.com,DIRECT"));
}

#[test]
fn delete_removes_a_rule() {
    let mut conf = parse(SAMPLE);
    // Drop rule 5 = GEOIP,CN,DIRECT
    conf.delete_rule(5);
    let rendered = render(&conf);
    assert!(!rendered.contains("GEOIP,CN,DIRECT"));
    // Other rules still there.
    assert!(rendered.contains("DOMAIN-SUFFIX,apple.com,DIRECT"));
    assert!(rendered.contains("FINAL,PROXY"));
}

#[test]
fn translate_emits_xray_routing_rules() {
    let conf = parse(SAMPLE);
    let result = translate(&conf);
    // Disabled rule + IP-ASN are dropped (1 disabled, 1 unsupported).
    assert!(result.skipped.iter().any(|s| s.reason.contains("IP-ASN")));
    // FINAL is intentionally skipped — nexray's routing preset is the true
    // catch-all and an emitted `network: tcp,udp` rule would mask it.
    assert!(result.skipped.iter().any(|s| s.reason.contains("FINAL")));
    let json = serde_json::to_string(&result.rules).expect("serialize");
    assert!(json.contains("\"domain:apple.com\""));
    assert!(json.contains("\"full:copilot.microsoft.com\""));
    assert!(json.contains("\"10.0.0.0/8\""));
    assert!(json.contains("\"geoip:cn\""));
    // FINAL → dropped, not emitted as a catch-all network rule.
    assert!(!json.contains("\"network\":\"tcp,udp\""));
}

#[test]
fn translates_quic_block_and_pattern() {
    // Enabled `AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP` —
    // the canonical Shadowrocket "block QUIC" idiom. We collapse it
    // into a single xray rule with `network` + `port` since xray's
    // per-rule fields are conjunctive.
    let src = "[Rule]\nAND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP\n";
    let conf = parse(src);
    let result = translate(&conf);
    assert!(
        result.skipped.is_empty(),
        "expected no skipped rules, got {:?}",
        result.skipped,
    );
    assert_eq!(result.rules.len(), 1);
    let json = serde_json::to_string(&result.rules[0]).expect("serialize");
    assert!(json.contains("\"network\":\"udp\""), "got: {json}");
    assert!(json.contains("\"port\":\"443\""), "got: {json}");
    assert!(json.contains("\"outboundTag\":\"block\""), "got: {json}");

    // Reverse ordering of the two inner clauses must produce the same
    // output — Shadowrocket users write either form interchangeably.
    let swapped = "[Rule]\nAND,((DEST-PORT,443),(PROTOCOL,UDP)),REJECT\n";
    let result = translate(&parse(swapped));
    assert!(result.skipped.is_empty());
    let json = serde_json::to_string(&result.rules[0]).expect("serialize");
    assert!(json.contains("\"network\":\"udp\""));
    assert!(json.contains("\"port\":\"443\""));

    // Anything else starting with AND still falls through to the
    // unsupported-skip reason.
    let unhandled = "[Rule]\nAND,((DOMAIN-SUFFIX,foo.com),(DEST-PORT,443)),PROXY\n";
    let result = translate(&parse(unhandled));
    assert!(result.rules.is_empty());
    assert!(result.skipped.iter().any(|s| s.reason.starts_with("AND:")));
}

#[test]
fn parses_real_default_conf() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("conf")
        .join("default.conf");
    if !path.exists() {
        // Skip when the file isn't checked in to this checkout.
        return;
    }
    let text = std::fs::read_to_string(&path).expect("read default.conf");
    let conf = parse(&text);
    let rule_count = conf.rules().count();
    assert!(rule_count > 100, "expected lots of rules, got {rule_count}");
    let result = translate(&conf);
    assert!(result.rules.len() > 100, "expected many translated rules");
    // Round-trip property: re-parsing the rendered output should produce
    // the same rule count.
    let rendered = render(&conf);
    let conf2 = parse(&rendered);
    assert_eq!(conf.rules().count(), conf2.rules().count());
}
