//! Decode/encode `vless://` share links. Pure: no IO, no panics on
//! adversarial input. 1:1 with `src/lib/share-link.ts`.

use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::skip_reason::SkipReason;
use crate::types_gen::{Alpn, CdnWsProfile, Fingerprint, Profile, RealityProfile, TrojanProfile};

/// Result of decoding a single share link.
///
/// `Ok` carries a full `Profile` (~250 bytes); `Err` carries only a reason +
/// the offending raw string (~25 bytes). The variant size delta would normally
/// trigger `clippy::large_enum_variant`, but boxing every successful parse to
/// shrink the failure path is the wrong trade — the common case is success,
/// and `DecodeResult` is transient (matched and dropped within the classifier).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum DecodeResult {
    Ok { profile: Profile },
    Err { reason: SkipReason, raw: String },
}

impl DecodeResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, DecodeResult::Ok { .. })
    }
}

/// Decode a single share link. Pure. Mirrors `decodeShareLink` in
/// `src/lib/share-link.ts`. Always returns a structured result — never panics.
pub fn decode_share_link(raw: &str) -> DecodeResult {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return err(SkipReason::Malformed, raw);
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("vmess://") {
        return err(SkipReason::VmessLegacy, raw);
    }
    if lower.starts_with("ss://") || lower.starts_with("ssr://") {
        return err(SkipReason::ShadowsocksLegacy, raw);
    }
    // trojan-go is a separate, incompatible fork; still refused. Plain
    // `trojan://` over TCP+TLS is parsed below.
    if lower.starts_with("trojan-go://") {
        return err(SkipReason::TrojanGoLegacy, raw);
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return err(SkipReason::HttpUnsupported, raw);
    }
    if lower.starts_with("socks://") || lower.starts_with("socks5://") {
        return err(SkipReason::SocksUnsupported, raw);
    }
    if lower.starts_with("trojan://") {
        return decode_trojan(trimmed);
    }
    if !lower.starts_with("vless://") {
        return err(SkipReason::UnknownProtocol, raw);
    }

    let Ok(url) = Url::parse(trimmed) else {
        return err(SkipReason::Malformed, raw);
    };

    let uuid = decode_pct(url.username());
    let address = url.host_str().unwrap_or("").to_string();
    let Some(port) = url.port() else {
        return err(SkipReason::Malformed, raw);
    };
    if uuid.is_empty() || address.is_empty() {
        return err(SkipReason::Malformed, raw);
    }

    if Uuid::parse_str(&uuid).is_err() {
        return err(SkipReason::Malformed, raw);
    }

    let q: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let remark = url.fragment().map(decode_pct).filter(|s| !s.is_empty());

    let network = q
        .get("type")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let security = q
        .get("security")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    if network == "kcp" {
        return err(SkipReason::VlessKcp, raw);
    }
    if network == "quic" {
        return err(SkipReason::VlessQuic, raw);
    }

    if security == "reality" {
        match network.as_str() {
            "ws" => return err(SkipReason::RealityWs, raw),
            "grpc" => return err(SkipReason::RealityGrpc, raw),
            "xhttp" => return err(SkipReason::RealityXhttp, raw),
            "httpupgrade" => return err(SkipReason::RealityHttpUpgrade, raw),
            "tcp" => {}
            _ => return err(SkipReason::Malformed, raw),
        }
        return parse_reality(raw, &uuid, &address, port, &q, remark.as_deref());
    }

    if security == "tls" && network != "ws" {
        return err(SkipReason::VlessTlsDirect, raw);
    }
    if security.is_empty() || security == "none" {
        return err(SkipReason::VlessTlsDirect, raw);
    }

    if network == "ws" && security == "tls" {
        return parse_cdn_ws(raw, &uuid, &address, port, &q, remark.as_deref());
    }

    err(SkipReason::Malformed, raw)
}

fn parse_cdn_ws(
    raw: &str,
    uuid: &str,
    address: &str,
    port: u16,
    q: &std::collections::HashMap<String, String>,
    remark: Option<&str>,
) -> DecodeResult {
    let host = q
        .get("host")
        .map(String::as_str)
        .unwrap_or(address)
        .to_string();
    let path = q.get("path").map(String::as_str).unwrap_or("/").to_string();
    let sni = q
        .get("sni")
        .map(String::as_str)
        .unwrap_or(host.as_str())
        .to_string();
    let encryption = q
        .get("encryption")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "none".into());
    if encryption != "none" {
        return err(SkipReason::Malformed, raw);
    }
    let Some(fingerprint) = pick_fingerprint(q.get("fp").map(String::as_str)) else {
        return err(SkipReason::Malformed, raw);
    };
    let alpn = parse_alpn(q.get("alpn").map(String::as_str));

    if host.is_empty() || path.is_empty() || sni.is_empty() {
        return err(SkipReason::Malformed, raw);
    }

    let id = profile_id("cdn-ws", address, port, uuid);
    let name = remark
        .filter(|s| !s.is_empty())
        .map(|s| truncate_chars(s, 64))
        .unwrap_or_else(|| format!("{address}:{port}"));

    let profile = CdnWsProfile {
        id,
        name,
        remark: remark.map(|s| s.to_string()),
        address: address.to_string(),
        port,
        uuid: uuid.to_string(),
        host,
        path,
        sni,
        alpn,
        fingerprint,
    };
    DecodeResult::Ok {
        profile: Profile::CdnWs(profile),
    }
}

fn decode_trojan(raw: &str) -> DecodeResult {
    let Ok(url) = Url::parse(raw) else {
        return err(SkipReason::Malformed, raw);
    };

    let password = decode_pct(url.username());
    let address = url.host_str().unwrap_or("").to_string();
    let Some(port) = url.port() else {
        return err(SkipReason::Malformed, raw);
    };
    if password.is_empty() || address.is_empty() {
        return err(SkipReason::Malformed, raw);
    }

    let q: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let remark = url.fragment().map(decode_pct).filter(|s| !s.is_empty());

    let network = q
        .get("type")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "tcp".into());
    if network == "ws" {
        return err(SkipReason::TrojanWs, raw);
    }
    if network != "tcp" {
        return err(SkipReason::Malformed, raw);
    }

    // Trojan defaults to TLS; refuse `security=none` outright.
    let security = q
        .get("security")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "tls".into());
    if security != "tls" {
        return err(SkipReason::Malformed, raw);
    }

    // DEVELOPMENT.md §4.1: never accept allowInsecure=1.
    if let Some(v) = q.get("allowInsecure") {
        let v = v.to_ascii_lowercase();
        if v == "1" || v == "true" {
            return err(SkipReason::Malformed, raw);
        }
    }

    let sni = q
        .get("sni")
        .or_else(|| q.get("peer"))
        .map(String::as_str)
        .unwrap_or(address.as_str())
        .to_string();
    if sni.is_empty() {
        return err(SkipReason::Malformed, raw);
    }

    let Some(fingerprint) = pick_fingerprint(q.get("fp").map(String::as_str)) else {
        return err(SkipReason::Malformed, raw);
    };
    let alpn = parse_alpn(q.get("alpn").map(String::as_str));

    let id = profile_id("trojan", &address, port, &password);
    let name = remark
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| truncate_chars(s, 64))
        .unwrap_or_else(|| format!("{address}:{port}"));

    let profile = TrojanProfile {
        id,
        name,
        remark: remark.map(|s| s.to_string()),
        address,
        port,
        password,
        sni,
        alpn,
        fingerprint,
    };
    DecodeResult::Ok {
        profile: Profile::Trojan(profile),
    }
}

fn parse_reality(
    raw: &str,
    uuid: &str,
    address: &str,
    port: u16,
    q: &std::collections::HashMap<String, String>,
    remark: Option<&str>,
) -> DecodeResult {
    let sni = q.get("sni").cloned().unwrap_or_default();
    let public_key = q.get("pbk").cloned().unwrap_or_default();
    let short_id_raw = q.get("sid").cloned().unwrap_or_default();
    let flow = q.get("flow").map(String::as_str).unwrap_or("");
    let encryption = q
        .get("encryption")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "none".into());
    let spider_x = q.get("spx").cloned().unwrap_or_default();

    if encryption != "none" || flow != "xtls-rprx-vision" {
        return err(SkipReason::Malformed, raw);
    }

    let Some(fingerprint) = pick_fingerprint(q.get("fp").map(String::as_str)) else {
        return err(SkipReason::Malformed, raw);
    };

    if sni.is_empty() || !is_reality_pbk(&public_key) {
        return err(SkipReason::Malformed, raw);
    }
    let Some(short_id) = normalize_short_id(&short_id_raw) else {
        return err(SkipReason::Malformed, raw);
    };

    let id = profile_id("reality", address, port, uuid);
    let name = remark
        .filter(|s| !s.is_empty())
        .map(|s| truncate_chars(s, 64))
        .unwrap_or_else(|| format!("{address}:{port}"));

    let profile = RealityProfile {
        id,
        name,
        remark: remark.map(|s| s.to_string()),
        address: address.to_string(),
        port,
        uuid: uuid.to_string(),
        sni,
        public_key,
        short_id,
        fingerprint,
        flow: "xtls-rprx-vision".to_string(),
        spider_x,
    };
    DecodeResult::Ok {
        profile: Profile::Reality(profile),
    }
}

// Both regexes are compile-time constants; the `expect` is the canonical
// pattern for static regex initialization. Per DEVELOPMENT.md §11 we exempt
// these by lint-allow attribute rather than letting them slip into other code.
#[allow(clippy::expect_used)]
fn is_reality_pbk(s: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_-]{43}=?$").expect("static regex"))
        .is_match(s)
}

#[allow(clippy::expect_used)]
fn normalize_short_id(s: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^([0-9a-fA-F]{2}){0,8}$").expect("static regex"));
    if !re.is_match(s) {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

fn pick_fingerprint(value: Option<&str>) -> Option<Fingerprint> {
    let Some(v) = value else {
        return Some(Fingerprint::Chrome);
    };
    if v.is_empty() {
        return Some(Fingerprint::Chrome);
    }
    let lower = v.to_ascii_lowercase();
    crate::FINGERPRINTS
        .iter()
        .find(|(_, name)| *name == lower)
        .map(|(fp, _)| *fp)
}

fn parse_alpn(value: Option<&str>) -> Vec<Alpn> {
    let default = || vec![Alpn::H2, Alpn::Http11];
    let Some(v) = value else { return default() };
    if v.is_empty() {
        return default();
    }
    let mut out = Vec::new();
    for part in v.split(',') {
        let t = part.trim();
        match t {
            "h2" => out.push(Alpn::H2),
            "http/1.1" => out.push(Alpn::Http11),
            _ => {}
        }
    }
    if out.is_empty() {
        default()
    } else {
        out
    }
}

/// Encode a Profile back to a `vless://...` (or `trojan://...`) URL. Pure,
/// mirrors `encodeShareLink`.
pub fn encode_share_link(profile: &Profile) -> String {
    let (credential, address, port) = match profile {
        Profile::CdnWs(p) => (&p.uuid, &p.address, p.port),
        Profile::Reality(p) => (&p.uuid, &p.address, p.port),
        Profile::Trojan(p) => (&p.password, &p.address, p.port),
    };

    let user = pct_encode(credential);
    let mut query = String::new();
    let mut push = |k: &str, v: &str| {
        if !query.is_empty() {
            query.push('&');
        }
        query.push_str(k);
        query.push('=');
        query.push_str(&pct_encode_query(v));
    };

    let remark = match profile {
        Profile::CdnWs(p) => {
            push("type", "ws");
            push("security", "tls");
            push("encryption", "none");
            push("host", &p.host);
            push("path", &p.path);
            push("sni", &p.sni);
            push("fp", fingerprint_str(p.fingerprint));
            let alpns: Vec<&str> = p.alpn.iter().map(|a| alpn_str(*a)).collect();
            push("alpn", &alpns.join(","));
            p.remark.as_deref()
        }
        Profile::Reality(p) => {
            push("type", "tcp");
            push("security", "reality");
            push("encryption", "none");
            push("flow", &p.flow);
            push("sni", &p.sni);
            push("pbk", &p.public_key);
            push("sid", &p.short_id);
            push("fp", fingerprint_str(p.fingerprint));
            if !p.spider_x.is_empty() {
                push("spx", &p.spider_x);
            }
            p.remark.as_deref()
        }
        Profile::Trojan(p) => {
            push("type", "tcp");
            push("security", "tls");
            push("sni", &p.sni);
            push("fp", fingerprint_str(p.fingerprint));
            let alpns: Vec<&str> = p.alpn.iter().map(|a| alpn_str(*a)).collect();
            push("alpn", &alpns.join(","));
            p.remark.as_deref()
        }
    };

    let scheme = if matches!(profile, Profile::Trojan(_)) {
        "trojan"
    } else {
        "vless"
    };
    let mut out = format!("{scheme}://{user}@{address}:{port}?{query}");
    if let Some(r) = remark {
        if !r.is_empty() {
            out.push('#');
            out.push_str(&pct_encode(r));
        }
    }
    out
}

fn fingerprint_str(fp: Fingerprint) -> &'static str {
    crate::FINGERPRINTS
        .iter()
        .find(|(f, _)| *f == fp)
        .map(|(_, n)| *n)
        .unwrap_or("chrome")
}

fn alpn_str(a: Alpn) -> &'static str {
    match a {
        Alpn::H2 => "h2",
        Alpn::Http11 => "http/1.1",
    }
}

/// FNV-1a 32-bit hex of `${kind}:${address}:${port}:${uuid}`. Mirrors the TS
/// `profileId` helper; outputs the same 8-char hex for the same inputs.
fn profile_id(kind: &str, address: &str, port: u16, uuid: &str) -> String {
    let s = format!("{kind}:{address}:{port}:{uuid}");
    let mut h: u32 = 0x811c9dc5;
    for b in s.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    format!("{h:08x}")
}

fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn decode_pct(s: &str) -> String {
    percent_decode(s).unwrap_or_else(|| s.to_string())
}

/// Minimal RFC 3986 percent-decode for ASCII inputs. Returns `None` on a
/// truncated escape — caller falls back to the raw string.
fn percent_decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            out.push(((hi << 4) | lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Conservative pct-encoder for fragment / userinfo. Encodes everything that
/// isn't ASCII unreserved.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

/// Pct-encoder for the query value half. Same alphabet as `pct_encode` plus
/// some extras we know are safe to leave unescaped (none, currently).
fn pct_encode_query(s: &str) -> String {
    pct_encode(s)
}

fn err(reason: SkipReason, raw: &str) -> DecodeResult {
    DecodeResult::Err {
        reason,
        raw: raw.to_string(),
    }
}
