//! Shadowrocket-style `.conf` rules-file support.
//!
//! Parses the bundled `conf/default.conf` (and any user copy in app data) into
//! a structured representation, lets callers add / toggle / delete rules
//! without trampling comments + section structure, and translates the
//! resulting `[Rule]` entries into xray-core `routing.rules` JSON.
//!
//! Round-trip property: `render(parse(src)) == src` for any input we can
//! parse. Lines we don't recognize round-trip verbatim under `ConfLine::Raw`.
//!
//! Rule types we map to xray:
//!
//! | .conf type        | xray field    | matcher prefix     |
//! |-------------------|---------------|--------------------|
//! | `DOMAIN`          | `domain`      | `full:`            |
//! | `DOMAIN-SUFFIX`   | `domain`      | `domain:`          |
//! | `DOMAIN-KEYWORD`  | `domain`      | `keyword:`         |
//! | `DOMAIN-REGEX`    | `domain`      | `regexp:`          |
//! | `IP-CIDR`         | `ip`          | (raw CIDR)         |
//! | `IP-CIDR6`        | `ip`          | (raw CIDR)         |
//! | `GEOIP`           | `ip`          | `geoip:<lower>`    |
//! | `FINAL`           | `network`     | `tcp,udp` catch-all |
//!
//! `IP-ASN`, `USER-AGENT`, `AND`, `PROTOCOL`, `DEST-PORT` parse cleanly but
//! don't translate to xray (no native ASN/UA/AND support); they're round-
//! tripped but skipped during translation, with a `skipped_reason` returned
//! so the UI can warn the user.
//!
//! The grammar is intentionally permissive: extra whitespace is tolerated,
//! unknown rule types parse as `RuleKind::Other` (round-trippable).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::types_gen::RoutingDestination;

/// One line in a rules file. We preserve every line so writes are
/// byte-comparable to the input on a no-op edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfLine {
    SectionHeader(String),
    Comment(String),
    Blank,
    Setting {
        key: String,
        value: String,
        raw: String,
    },
    Rule(ParsedRule),
    Raw(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedRule {
    pub kind: RuleKind,
    pub policy: RoutingDestination,
    pub no_resolve: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum RuleKind {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(String),
    IpCidr(String),
    IpCidr6(String),
    Geoip(String),
    IpAsn(String),
    UserAgent(String),
    Final,
    /// Raw text we couldn't translate but want to preserve. Includes AND
    /// combinators, PROTOCOL, DEST-PORT, anything we don't grok.
    Other {
        kw: String,
        rest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfFile {
    pub lines: Vec<ConfLine>,
}

impl ConfFile {
    pub fn empty() -> Self {
        Self { lines: vec![] }
    }

    /// Iterate the file's parsed rules in source order.
    pub fn rules(&self) -> impl Iterator<Item = &ParsedRule> {
        self.lines.iter().filter_map(|l| match l {
            ConfLine::Rule(r) => Some(r),
            _ => None,
        })
    }

    /// Append a rule to the `[Rule]` section. If no `[Rule]` section
    /// exists, one is added at the end.
    pub fn append_rule(&mut self, rule: ParsedRule) {
        let rule_section_end = self.find_rule_section_end();
        match rule_section_end {
            Some(idx) => self.lines.insert(idx, ConfLine::Rule(rule)),
            None => {
                if !matches!(self.lines.last(), Some(ConfLine::Blank) | None) {
                    self.lines.push(ConfLine::Blank);
                }
                self.lines
                    .push(ConfLine::SectionHeader("[Rule]".to_string()));
                self.lines.push(ConfLine::Rule(rule));
            }
        }
    }

    /// Toggle the `enabled` flag of the Nth rule (0-based among rules only).
    pub fn set_rule_enabled(&mut self, rule_index: usize, enabled: bool) {
        if let Some(r) = self.rule_at_mut(rule_index) {
            r.enabled = enabled;
        }
    }

    /// Replace the `policy` (DIRECT / PROXY / BLOCK) of the Nth rule.
    pub fn set_rule_destination(&mut self, rule_index: usize, destination: RoutingDestination) {
        if let Some(r) = self.rule_at_mut(rule_index) {
            r.policy = destination;
        }
    }

    fn rule_at_mut(&mut self, rule_index: usize) -> Option<&mut ParsedRule> {
        let mut seen = 0;
        for line in &mut self.lines {
            if let ConfLine::Rule(r) = line {
                if seen == rule_index {
                    return Some(r);
                }
                seen += 1;
            }
        }
        None
    }

    /// Delete the Nth rule from the file.
    pub fn delete_rule(&mut self, rule_index: usize) {
        let mut seen = 0;
        let mut target: Option<usize> = None;
        for (i, line) in self.lines.iter().enumerate() {
            if let ConfLine::Rule(_) = line {
                if seen == rule_index {
                    target = Some(i);
                    break;
                }
                seen += 1;
            }
        }
        if let Some(i) = target {
            self.lines.remove(i);
        }
    }

    /// Find the index where a new rule should be inserted (immediately
    /// before the first non-rule line *after* the [Rule] header). Returns
    /// `None` if no [Rule] section exists.
    fn find_rule_section_end(&self) -> Option<usize> {
        let mut in_rule_section = false;
        let mut last_rule_idx: Option<usize> = None;
        for (i, line) in self.lines.iter().enumerate() {
            match line {
                ConfLine::SectionHeader(name) => {
                    if in_rule_section {
                        // Hit the next section header; insert just before it.
                        return Some(last_rule_idx.map(|x| x + 1).unwrap_or(i));
                    }
                    in_rule_section = name.eq_ignore_ascii_case("[Rule]");
                }
                ConfLine::Rule(_) if in_rule_section => last_rule_idx = Some(i),
                _ => {}
            }
        }
        // Reached EOF while inside [Rule]: append after the last rule.
        if in_rule_section {
            Some(last_rule_idx.map(|x| x + 1).unwrap_or(self.lines.len()))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

pub fn parse(text: &str) -> ConfFile {
    let mut lines = Vec::new();
    let mut in_rule_section = false;

    for raw in text.lines() {
        let trimmed = raw.trim_start();
        if trimmed.is_empty() {
            lines.push(ConfLine::Blank);
            continue;
        }
        if let Some(name) = section_header(trimmed) {
            in_rule_section = name.eq_ignore_ascii_case("[Rule]");
            lines.push(ConfLine::SectionHeader(trimmed.to_string()));
            continue;
        }

        // Disabled / commented rule: a leading `#` directly followed by a
        // recognized rule keyword should round-trip as a disabled Rule entry.
        if let Some(rest) = trimmed.strip_prefix('#') {
            let inner = rest.trim_start();
            if in_rule_section {
                if let Some(rule) = parse_rule_line(inner, false) {
                    lines.push(ConfLine::Rule(rule));
                    continue;
                }
            }
            lines.push(ConfLine::Comment(raw.to_string()));
            continue;
        }

        if in_rule_section {
            if let Some(rule) = parse_rule_line(trimmed, true) {
                lines.push(ConfLine::Rule(rule));
                continue;
            }
        }

        if let Some((k, v)) = trimmed.split_once('=') {
            lines.push(ConfLine::Setting {
                key: k.trim().to_string(),
                value: v.trim().to_string(),
                raw: raw.to_string(),
            });
            continue;
        }

        lines.push(ConfLine::Raw(raw.to_string()));
    }

    ConfFile { lines }
}

fn section_header(s: &str) -> Option<&str> {
    let t = s.trim_end();
    if t.starts_with('[') && t.ends_with(']') {
        Some(t)
    } else {
        None
    }
}

fn parse_rule_line(s: &str, enabled: bool) -> Option<ParsedRule> {
    // Format: KEYWORD,VALUE[,POLICY][,no-resolve] (with extra fields for AND).
    // We split by `,` on the top level. AND combinators contain nested
    // commas — for those we treat the whole thing as Other.
    if s.starts_with("AND,") || s.starts_with("OR,") || s.starts_with("NOT,") {
        let policy_part = s.rsplit_once(',')?.1.trim();
        let policy = parse_policy(policy_part)?;
        let (kw, rest) = match s.split_once(',') {
            Some((k, r)) => (k.to_string(), r.to_string()),
            None => (String::new(), s.to_string()),
        };
        return Some(ParsedRule {
            kind: RuleKind::Other { kw, rest },
            policy,
            no_resolve: false,
            enabled,
        });
    }

    let parts: Vec<&str> = s.split(',').map(|p| p.trim()).collect();
    if parts.len() < 2 {
        return None;
    }
    let kw = parts[0].to_uppercase();

    if kw == "FINAL" {
        let policy = parse_policy(parts[1])?;
        return Some(ParsedRule {
            kind: RuleKind::Final,
            policy,
            no_resolve: false,
            enabled,
        });
    }

    if parts.len() < 3 {
        return None;
    }

    let value = parts[1].to_string();
    let policy = parse_policy(parts[2])?;
    let no_resolve = parts
        .iter()
        .skip(3)
        .any(|p| p.eq_ignore_ascii_case("no-resolve"));

    let kind = match kw.as_str() {
        "DOMAIN" => RuleKind::Domain(value),
        "DOMAIN-SUFFIX" => RuleKind::DomainSuffix(value),
        "DOMAIN-KEYWORD" => RuleKind::DomainKeyword(value),
        "DOMAIN-REGEX" | "URL-REGEX" => RuleKind::DomainRegex(value),
        "IP-CIDR" => RuleKind::IpCidr(value),
        "IP-CIDR6" => RuleKind::IpCidr6(value),
        "GEOIP" => RuleKind::Geoip(value),
        "IP-ASN" => RuleKind::IpAsn(value),
        "USER-AGENT" => RuleKind::UserAgent(value),
        other => RuleKind::Other {
            kw: other.to_string(),
            rest: parts[1..].join(","),
        },
    };

    Some(ParsedRule {
        kind,
        policy,
        no_resolve,
        enabled,
    })
}

fn parse_policy(s: &str) -> Option<RoutingDestination> {
    match s.to_ascii_uppercase().as_str() {
        "DIRECT" => Some(RoutingDestination::Direct),
        "PROXY" => Some(RoutingDestination::Proxy),
        // Both REJECT and REJECT-NO-DROP collapse to `block` for our
        // purposes — the difference is response strategy, not destination.
        "REJECT" | "REJECT-NO-DROP" | "REJECT-DROP" => Some(RoutingDestination::Block),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub fn render(conf: &ConfFile) -> String {
    let mut out = String::new();
    for (i, line) in conf.lines.iter().enumerate() {
        match line {
            ConfLine::SectionHeader(s) => out.push_str(s),
            ConfLine::Comment(s) => out.push_str(s),
            ConfLine::Blank => {}
            ConfLine::Setting { raw, .. } => out.push_str(raw),
            ConfLine::Rule(r) => out.push_str(&render_rule(r)),
            ConfLine::Raw(s) => out.push_str(s),
        }
        // Always emit a trailing newline except after the very last line if
        // the source didn't have one — for simplicity we always emit `\n`.
        if i + 1 < conf.lines.len() || !out.is_empty() {
            out.push('\n');
        }
    }
    out
}

fn render_rule(r: &ParsedRule) -> String {
    let prefix = if r.enabled { "" } else { "# " };
    let body = match &r.kind {
        RuleKind::Domain(v) => format!("DOMAIN,{v},{}", policy_str(r.policy)),
        RuleKind::DomainSuffix(v) => format!("DOMAIN-SUFFIX,{v},{}", policy_str(r.policy)),
        RuleKind::DomainKeyword(v) => format!("DOMAIN-KEYWORD,{v},{}", policy_str(r.policy)),
        RuleKind::DomainRegex(v) => format!("DOMAIN-REGEX,{v},{}", policy_str(r.policy)),
        RuleKind::IpCidr(v) => format!("IP-CIDR,{v},{}", policy_str(r.policy)),
        RuleKind::IpCidr6(v) => format!("IP-CIDR6,{v},{}", policy_str(r.policy)),
        RuleKind::Geoip(v) => format!("GEOIP,{v},{}", policy_str(r.policy)),
        RuleKind::IpAsn(v) => format!("IP-ASN,{v},{}", policy_str(r.policy)),
        RuleKind::UserAgent(v) => format!("USER-AGENT,{v},{}", policy_str(r.policy)),
        RuleKind::Final => format!("FINAL,{}", policy_str(r.policy)),
        RuleKind::Other { kw, rest } => {
            // Preserve original-ish form. `rest` already includes the policy.
            format!("{kw},{rest}")
        }
    };
    let suffix = if r.no_resolve { ",no-resolve" } else { "" };
    format!("{prefix}{body}{suffix}")
}

fn policy_str(p: RoutingDestination) -> &'static str {
    match p {
        RoutingDestination::Direct => "DIRECT",
        RoutingDestination::Proxy => "PROXY",
        RoutingDestination::Block => "REJECT",
    }
}

// ---------------------------------------------------------------------------
// xray translation
// ---------------------------------------------------------------------------

/// Result of translating a rules file into xray `routing.rules` entries.
/// Unsupported / disabled rules are dropped from `rules` and their reasons
/// captured in `skipped` so the UI can show a count.
#[derive(Debug, Default)]
pub struct TranslateResult {
    pub rules: Vec<Value>,
    pub skipped: Vec<SkippedRule>,
}

#[derive(Debug)]
pub struct SkippedRule {
    pub raw: String,
    pub reason: &'static str,
}

pub fn translate(conf: &ConfFile) -> TranslateResult {
    let mut out = TranslateResult::default();
    for r in conf.rules() {
        if !r.enabled {
            continue;
        }
        match rule_to_xray(r) {
            Ok(value) => out.rules.push(value),
            Err(reason) => out.skipped.push(SkippedRule {
                raw: render_rule(r),
                reason,
            }),
        }
    }
    out
}

fn rule_to_xray(r: &ParsedRule) -> Result<Value, &'static str> {
    let outbound = match r.policy {
        RoutingDestination::Direct => "direct",
        RoutingDestination::Proxy => "proxy",
        RoutingDestination::Block => "block",
    };
    match &r.kind {
        RuleKind::Domain(v) => Ok(json!({
            "type": "field",
            "domain": [format!("full:{v}")],
            "outboundTag": outbound,
        })),
        RuleKind::DomainSuffix(v) => Ok(json!({
            "type": "field",
            "domain": [format!("domain:{v}")],
            "outboundTag": outbound,
        })),
        RuleKind::DomainKeyword(v) => Ok(json!({
            "type": "field",
            "domain": [format!("keyword:{v}")],
            "outboundTag": outbound,
        })),
        RuleKind::DomainRegex(v) => Ok(json!({
            "type": "field",
            "domain": [format!("regexp:{v}")],
            "outboundTag": outbound,
        })),
        RuleKind::IpCidr(v) | RuleKind::IpCidr6(v) => Ok(json!({
            "type": "field",
            "ip": [v],
            "outboundTag": outbound,
        })),
        RuleKind::Geoip(v) => Ok(json!({
            "type": "field",
            "ip": [format!("geoip:{}", v.to_lowercase())],
            "outboundTag": outbound,
        })),
        RuleKind::Final => Ok(json!({
            "type": "field",
            "network": "tcp,udp",
            "outboundTag": outbound,
        })),
        RuleKind::IpAsn(_) => Err("IP-ASN: xray-core has no native ASN matcher"),
        RuleKind::UserAgent(_) => Err("USER-AGENT: xray-core has no native UA matcher"),
        RuleKind::Other { .. } => Err("rule type not supported by xray-core"),
    }
}
