//! Detect-and-decode subscription bodies. Pure mirror of
//! `src/lib/subscription.ts`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::share_link::{decode_share_link, DecodeResult};
use crate::skip_reason::SkipReason;
use crate::types_gen::Profile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedEntry {
    pub raw: String,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyResult {
    pub accepted: Vec<Profile>,
    pub skipped: Vec<SkippedEntry>,
}

/// Classify a subscription body. Mirrors `classifySubscription` in TS.
pub fn classify_subscription(body: &str) -> ClassifyResult {
    let unwrapped = decode_if_base64(body);
    let mut accepted = Vec::new();
    let mut skipped = Vec::new();

    for raw in unwrapped.split(['\n', '\r']) {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match decode_share_link(line) {
            DecodeResult::Ok { profile } => accepted.push(profile),
            DecodeResult::Err { reason, raw } => skipped.push(SkippedEntry { raw, reason }),
        }
    }

    ClassifyResult { accepted, skipped }
}

/// Format the skipped-list summary line per DEVELOPMENT.md §5.3, e.g.
///   `5 servers skipped: 2 vmess (legacy), 1 shadowsocks (legacy), ...`
///
/// Ordered by descending count, ties broken alphabetically. Empty input → "".
pub fn summarize_skipped(skipped: &[SkippedEntry]) -> String {
    if skipped.is_empty() {
        return String::new();
    }
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for s in skipped {
        *counts.entry(s.reason.as_str()).or_insert(0) += 1;
    }
    let mut entries: Vec<(&'static str, usize)> = counts.into_iter().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let parts: Vec<String> = entries
        .into_iter()
        .map(|(reason, n)| format!("{n} {reason}"))
        .collect();
    format!("{} servers skipped: {}", skipped.len(), parts.join(", "))
}

/// Heuristic: a body is base64 if (a) no line in the original starts with a
/// known share-link scheme, (b) the stripped alphabet is base64, and (c)
/// the decoded text contains a known scheme. Mirrors the TS heuristic.
fn decode_if_base64(body: &str) -> String {
    if body.is_empty() {
        return body.to_string();
    }

    if any_line_has_scheme(body) {
        return body.to_string();
    }

    let stripped: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if stripped.is_empty() {
        return body.to_string();
    }
    if !stripped
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-' | b'='))
    {
        return body.to_string();
    }

    let normalized: String = stripped
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            _ => c,
        })
        .collect();
    let pad = (4 - (normalized.len() % 4)) % 4;
    let padded = format!("{}{}", normalized, "=".repeat(pad));

    let Ok(bytes) = STANDARD.decode(padded.as_bytes()) else {
        return body.to_string();
    };
    let Ok(decoded) = String::from_utf8(bytes) else {
        return body.to_string();
    };
    if decoded_has_scheme(&decoded) {
        decoded
    } else {
        body.to_string()
    }
}

fn any_line_has_scheme(body: &str) -> bool {
    for line in body.lines() {
        let t = line.trim_start();
        let lower = t.to_ascii_lowercase();
        for scheme in SCHEMES {
            if lower.starts_with(scheme) {
                return true;
            }
        }
    }
    false
}

fn decoded_has_scheme(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    for scheme in SCHEMES {
        if lower.contains(scheme) {
            return true;
        }
    }
    false
}

const SCHEMES: &[&str] = &[
    "vless://",
    "vmess://",
    "ss://",
    "ssr://",
    "trojan://",
    "trojan-go://",
    "http://",
    "https://",
    "socks://",
    "socks5://",
];

/// Reject `http://` subscription URLs at parse time (DEVELOPMENT.md §12 rule 1
/// + §5.4). Returns `Ok(())` for HTTPS, `Err(NotHttps)` otherwise.
pub fn require_https(url: &str) -> Result<(), crate::errors::CoreError> {
    let lower = url.trim_start().to_ascii_lowercase();
    if lower.starts_with("https://") {
        Ok(())
    } else {
        Err(crate::errors::CoreError::NotHttps(url.to_string()))
    }
}
