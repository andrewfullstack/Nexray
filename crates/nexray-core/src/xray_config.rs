//! `Profile` → xray-core JSON config materializer.
//!
//! Refuses to materialize when any mandatory field is empty/invalid (per
//! DEVELOPMENT.md §12 rule 4: never silently fill defaults that change
//! semantics). The Phase-0 Zod schema + share-link parser already validates
//! these at parse time; the second check here is the belt-and-braces guard
//! for code paths that build a `Profile` programmatically (e.g. tests).

use serde_json::{json, Value};
use thiserror::Error;

use crate::types_gen::{
    Alpn, CdnWsProfile, CustomRule, DnsConfig, Fingerprint, Profile, RealityProfile,
    RoutingDestination, RoutingMatcherType, RoutingPreset, RoutingSettings,
};

/// Knobs for the materialized config. None of these affect security
/// invariants — they're only about local listener ports and verbosity.
#[derive(Debug, Clone)]
pub struct XrayConfigOptions {
    /// SOCKS5 inbound port on `127.0.0.1`. Default: 10808.
    pub socks_port: u16,
    /// Stats API port on `127.0.0.1`, or `None` to disable the stats inbound.
    /// When `Some`, traffic counters become readable via the Stats API.
    pub stats_port: Option<u16>,
    /// xray-core log level. `"warning"` is a sensible default — `"info"` is
    /// chatty, `"none"` blinds the supervisor.
    pub log_level: &'static str,
    /// Routing preset + user overrides + DNS config. Defaults to the §6.1
    /// rule set so callers that don't care about routing get safe behaviour.
    pub routing: RoutingSettings,
    /// Pre-rendered xray `routing.rules` entries to weave between
    /// `custom_rules` and the preset. Used by the Tauri shell to inject
    /// rules parsed from the user's Shadowrocket-format `rules.conf` file.
    pub extra_rules: Vec<Value>,
    /// Optional source IP that the `direct` outbound binds to. When TUN
    /// mode captures all default-route traffic, an unbound `direct`
    /// outbound socket would route through the tunnel and create a loop
    /// (`socks-in → direct → utun → tun2socks → socks-in → ...`). Binding
    /// to the local interface's IP forces the kernel to use that
    /// interface regardless of the routing table. Leave `None` when TUN
    /// is off.
    pub direct_send_through: Option<String>,
}

impl Default for XrayConfigOptions {
    fn default() -> Self {
        Self {
            socks_port: 10808,
            stats_port: None,
            log_level: "warning",
            routing: default_routing_settings(),
            extra_rules: vec![],
            direct_send_through: None,
        }
    }
}

/// The Phase-0/§6.1 routing baseline. Used by `XrayConfigOptions::default`
/// and exposed for the Tauri shell's "reset to defaults" path.
pub fn default_routing_settings() -> RoutingSettings {
    RoutingSettings {
        preset: RoutingPreset::Default,
        custom_rules: vec![],
        dns: DnsConfig {
            domestic_resolver: "223.5.5.5".into(),
            proxy_resolver: "https://1.1.1.1/dns-query".into(),
        },
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MaterializeError {
    #[error("{kind}: mandatory field `{field}` is empty or invalid")]
    InvalidField {
        kind: &'static str,
        field: &'static str,
    },
}

/// Build the full xray-core JSON config from a Profile + options. Pure: no IO.
pub fn materialize(profile: &Profile, opts: &XrayConfigOptions) -> Result<Value, MaterializeError> {
    validate(profile)?;

    let outbound = match profile {
        Profile::CdnWs(p) => cdn_ws_outbound(p),
        Profile::Reality(p) => reality_outbound(p),
    };

    let mut inbounds = vec![json!({
        "tag": "socks-in",
        "port": opts.socks_port,
        "listen": "127.0.0.1",
        "protocol": "socks",
        "settings": { "auth": "noauth", "udp": true, "ip": "127.0.0.1" },
        "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    })];

    let direct_outbound = if let Some(ip) = opts.direct_send_through.as_deref() {
        // sendThrough binds the outbound socket to a specific source IP.
        // When TUN is on this is essential: without it, xray's direct
        // outbound dials through the kernel routing table — which now
        // points 0.0.0.0/1 + 128.0.0.0/1 at our utun device. The traffic
        // would loop back into tun2socks, hit socks-in again, and explode
        // into a cascade of `creating too many tcp ports` errors.
        json!({
            "tag": "direct",
            "protocol": "freedom",
            "settings": {},
            "sendThrough": ip,
        })
    } else {
        json!({ "tag": "direct", "protocol": "freedom", "settings": {} })
    };

    let mut outbounds = vec![
        outbound,
        direct_outbound,
        json!({ "tag": "block", "protocol": "blackhole", "settings": {} }),
    ];

    let mut routing_rules = routing_rules_with_extra(&opts.routing, &opts.extra_rules);
    let mut config = json!({
        "log": { "loglevel": opts.log_level },
        "dns": dns_for(&opts.routing.dns),
    });

    if let Some(stats_port) = opts.stats_port {
        // Stats API listener — bound 127.0.0.1 only (DEVELOPMENT.md §12 rule 6).
        inbounds.push(json!({
            "tag": "api-in",
            "port": stats_port,
            "listen": "127.0.0.1",
            "protocol": "dokodemo-door",
            "settings": { "address": "127.0.0.1" }
        }));
        outbounds.push(json!({ "tag": "api", "protocol": "freedom", "settings": {} }));
        config["api"] = json!({
            "tag": "api",
            "services": ["StatsService"],
        });
        config["stats"] = json!({});
        config["policy"] = json!({
            "system": {
                "statsInboundUplink": true,
                "statsInboundDownlink": true,
                "statsOutboundUplink": true,
                "statsOutboundDownlink": true
            }
        });
        // Route the api-in inbound to the api outbound. Placed first so it
        // wins over the catch-all `proxy` route at the end of the list.
        routing_rules.insert(
            0,
            json!({
                "type": "field",
                "inboundTag": ["api-in"],
                "outboundTag": "api"
            }),
        );
    }

    config["inbounds"] = Value::Array(inbounds);
    config["outbounds"] = Value::Array(outbounds);
    config["routing"] = json!({
        "domainStrategy": "IPIfNonMatch",
        "rules": routing_rules,
    });
    Ok(config)
}

// ---------------------------------------------------------------------------
// Outbounds
// ---------------------------------------------------------------------------

fn cdn_ws_outbound(p: &CdnWsProfile) -> Value {
    let alpn: Vec<&str> = p.alpn.iter().map(alpn_str).collect();
    json!({
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": p.address,
                "port": p.port,
                "users": [{ "id": p.uuid, "encryption": "none" }]
            }]
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "tlsSettings": {
                "serverName": p.sni,
                "alpn": alpn,
                "fingerprint": fingerprint_str(p.fingerprint),
                "allowInsecure": false
            },
            "wsSettings": {
                "path": p.path,
                "headers": { "Host": p.host }
            }
        }
    })
}

fn reality_outbound(p: &RealityProfile) -> Value {
    json!({
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": p.address,
                "port": p.port,
                "users": [{
                    "id": p.uuid,
                    "flow": "xtls-rprx-vision",
                    "encryption": "none"
                }]
            }]
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": p.sni,
                "fingerprint": fingerprint_str(p.fingerprint),
                "publicKey": p.public_key,
                "shortId": p.short_id,
                "spiderX": p.spider_x
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Routing & DNS — preset baselines + user overrides.
// DEVELOPMENT.md §6.1 default rule set lives in `preset_rules(Default)`.
// ---------------------------------------------------------------------------

/// Build the full rule list for a `RoutingSettings`: user overrides FIRST so
/// they win Xray's first-match-wins evaluation, preset rules after.
pub fn routing_rules_for(settings: &RoutingSettings) -> Vec<Value> {
    routing_rules_with_extra(settings, &[])
}

/// Same as `routing_rules_for` but interleaves `extra_rules` (e.g. parsed
/// from `rules.conf`) between user CustomRules and the preset baseline.
/// Order: in-memory CustomRules → extra_rules → preset.
pub fn routing_rules_with_extra(settings: &RoutingSettings, extra_rules: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = settings
        .custom_rules
        .iter()
        .filter(|r| r.enabled)
        .map(custom_rule_to_xray)
        .collect();
    out.extend(extra_rules.iter().cloned());
    out.extend(preset_rules(settings.preset));
    out
}

/// Translate a single `CustomRule` into Xray's `routing.rules[]` entry shape.
fn custom_rule_to_xray(rule: &CustomRule) -> Value {
    let mut entry = serde_json::Map::new();
    entry.insert("type".into(), Value::String("field".into()));
    match rule.matcher_type {
        RoutingMatcherType::Domain => {
            entry.insert("domain".into(), json!([rule.matcher]));
        }
        RoutingMatcherType::Ip => {
            entry.insert("ip".into(), json!([rule.matcher]));
        }
        RoutingMatcherType::Port => {
            entry.insert("port".into(), Value::String(rule.matcher.clone()));
        }
        RoutingMatcherType::Network => {
            entry.insert("network".into(), Value::String(rule.matcher.clone()));
        }
    }
    entry.insert(
        "outboundTag".into(),
        Value::String(destination_tag(rule.destination).into()),
    );
    Value::Object(entry)
}

fn destination_tag(d: RoutingDestination) -> &'static str {
    match d {
        RoutingDestination::Direct => "direct",
        RoutingDestination::Proxy => "proxy",
        RoutingDestination::Block => "block",
    }
}

/// Per-preset rule list.
///
/// - `default`: §6.1 — CN-direct, ads-block, rest-proxy.
/// - `direct`: only block ads + private; everything else direct. Useful when
///   the user wants the proxy off but still ad-filtered.
/// - `global`: only block ads + private; everything else proxy.
fn preset_rules(preset: RoutingPreset) -> Vec<Value> {
    let private = json!({ "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" });
    let ads =
        json!({ "type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block" });
    match preset {
        RoutingPreset::Default => vec![
            private,
            ads,
            // `geosite:microsoft-cn` was in DEVELOPMENT.md §6.1's original
            // list but doesn't exist in Loyalsoldier's geosite.dat (the
            // dataset we bundle); xray rejects the whole config if any
            // referenced category is missing. Microsoft-CN domains are
            // covered by the rules file's explicit `DOMAIN-SUFFIX` entries.
            json!({
                "type": "field",
                "domain": [
                    "geosite:cn",
                    "geosite:apple-cn",
                    "geosite:google-cn"
                ],
                "outboundTag": "direct"
            }),
            json!({ "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct" }),
            json!({ "type": "field", "network": "tcp,udp", "outboundTag": "proxy" }),
        ],
        RoutingPreset::Direct => vec![
            ads,
            json!({ "type": "field", "network": "tcp,udp", "outboundTag": "direct" }),
        ],
        RoutingPreset::Global => vec![
            private,
            ads,
            json!({ "type": "field", "network": "tcp,udp", "outboundTag": "proxy" }),
        ],
    }
}

/// DNS config per §6.1: AliDNS (domestic) for `geosite:cn`, DoH (proxy) for
/// everything not in CN. The `expectIPs: ["geoip:cn"]` filter on the domestic
/// resolver guards against poisoned answers — if Ali returns a non-CN IP for
/// a CN-listed domain we fall back to the proxy resolver.
pub fn dns_for(dns: &DnsConfig) -> Value {
    json!({
        "servers": [
            {
                "address": dns.proxy_resolver,
                "domains": ["geosite:geolocation-!cn"]
            },
            {
                "address": dns.domestic_resolver,
                "domains": ["geosite:cn"],
                "expectIPs": ["geoip:cn"]
            }
        ]
    })
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate(profile: &Profile) -> Result<(), MaterializeError> {
    match profile {
        Profile::CdnWs(p) => {
            check("cdn-ws", "address", !p.address.is_empty())?;
            check("cdn-ws", "uuid", !p.uuid.is_empty())?;
            check("cdn-ws", "host", !p.host.is_empty())?;
            check("cdn-ws", "path", !p.path.is_empty())?;
            check("cdn-ws", "sni", !p.sni.is_empty())?;
            check("cdn-ws", "alpn", !p.alpn.is_empty())?;
        }
        Profile::Reality(p) => {
            check("reality", "address", !p.address.is_empty())?;
            check("reality", "uuid", !p.uuid.is_empty())?;
            check("reality", "sni", !p.sni.is_empty())?;
            check("reality", "publicKey", !p.public_key.is_empty())?;
            check("reality", "flow", p.flow == "xtls-rprx-vision")?;
        }
    }
    Ok(())
}

fn check(kind: &'static str, field: &'static str, ok: bool) -> Result<(), MaterializeError> {
    if ok {
        Ok(())
    } else {
        Err(MaterializeError::InvalidField { kind, field })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fingerprint_str(fp: Fingerprint) -> &'static str {
    crate::FINGERPRINTS
        .iter()
        .find(|(f, _)| *f == fp)
        .map(|(_, n)| *n)
        .unwrap_or("chrome")
}

fn alpn_str(a: &Alpn) -> &'static str {
    match a {
        Alpn::H2 => "h2",
        Alpn::Http11 => "http/1.1",
    }
}
