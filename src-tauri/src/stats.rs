//! Stats API client. xray-core exposes a gRPC StatsService; the cheap way
//! to read it without pulling tonic + the .proto is to shell out to
//! `xray api statsquery --server 127.0.0.1:<stats_port> -pattern outbound>>>proxy>>>traffic`
//! and parse the response.
//!
//! xray 25.x emitted protobuf text (`stat: < name: "..." value: 12345 >`),
//! xray 26.x emits JSON (`{"stat":[{"name":"...","value":12345}]}`). We
//! parse both to keep working across the user's installed xray version.

use std::path::Path;
use std::time::Duration;

use nexray_core::TrafficStats;

pub struct StatsClient;

impl StatsClient {
    /// Build the "stats unavailable" sentinel. Used while xray isn't running
    /// or when the Stats API call returns no useful counters yet.
    pub fn unavailable() -> TrafficStats {
        TrafficStats {
            available: false,
            uplink_bytes: 0,
            downlink_bytes: 0,
        }
    }

    /// Run `xray api statsquery` against the in-process stats inbound and
    /// parse the response. Returns `unavailable()` on any failure (bad
    /// path, RPC error, parse error) so polling never throws.
    pub async fn fetch(xray_bin: &Path, stats_port: u16) -> TrafficStats {
        let server = format!("127.0.0.1:{stats_port}");
        let exec = tokio::process::Command::new(xray_bin)
            .args([
                "api",
                "statsquery",
                "--server",
                &server,
                "-pattern",
                "outbound>>>proxy>>>traffic",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .output();
        // Cap at 750ms — the call usually returns in <50ms; if xray is
        // unhealthy we'd rather show stale stats than wedge the poller.
        let output = match tokio::time::timeout(Duration::from_millis(750), exec).await {
            Ok(Ok(out)) => out,
            _ => return Self::unavailable(),
        };
        if !output.status.success() {
            return Self::unavailable();
        }
        let body = String::from_utf8_lossy(&output.stdout);
        Self::parse_stats_query(&body)
    }

    /// Parse `xray api statsquery` output. Tries JSON first (xray 26+),
    /// falls back to the protobuf text form (xray 25-).
    pub fn parse_stats_query(body: &str) -> TrafficStats {
        if let Some(parsed) = parse_json(body) {
            return parsed;
        }
        parse_proto_text(body)
    }
}

fn parse_json(body: &str) -> Option<TrafficStats> {
    #[derive(serde::Deserialize)]
    struct Resp {
        #[serde(default)]
        stat: Vec<Stat>,
    }
    #[derive(serde::Deserialize)]
    struct Stat {
        name: String,
        #[serde(default)]
        value: serde_json::Value,
    }
    let r: Resp = serde_json::from_str(body).ok()?;
    let mut up = 0u64;
    let mut down = 0u64;
    for s in &r.stat {
        let v = s
            .value
            .as_u64()
            .or_else(|| s.value.as_str().and_then(|s| s.parse().ok()))
            .unwrap_or(0);
        if s.name.contains("outbound>>>proxy>>>traffic>>>uplink") {
            up = up.saturating_add(v);
        } else if s.name.contains("outbound>>>proxy>>>traffic>>>downlink") {
            down = down.saturating_add(v);
        }
    }
    Some(TrafficStats {
        available: true,
        uplink_bytes: up,
        downlink_bytes: down,
    })
}

fn parse_proto_text(body: &str) -> TrafficStats {
    let mut up = 0u64;
    let mut down = 0u64;
    let mut current_name: Option<String> = None;
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed
            .strip_prefix("name: ")
            .or_else(|| trimmed.strip_prefix("Name: "))
        {
            let n = name.trim().trim_matches('"').to_string();
            current_name = Some(n);
            continue;
        }
        if let Some(value) = trimmed
            .strip_prefix("value: ")
            .or_else(|| trimmed.strip_prefix("Value: "))
        {
            let v: u64 = value.trim().parse().unwrap_or(0);
            if let Some(name) = &current_name {
                if name.contains("outbound>>>proxy>>>traffic>>>uplink") {
                    up = up.saturating_add(v);
                } else if name.contains("outbound>>>proxy>>>traffic>>>downlink") {
                    down = down.saturating_add(v);
                }
            }
        }
    }
    TrafficStats {
        available: true,
        uplink_bytes: up,
        downlink_bytes: down,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    const SAMPLE_PROTO: &str = r#"
stat: <
    name: "outbound>>>proxy>>>traffic>>>uplink"
    value: 12345
>
stat: <
    name: "outbound>>>proxy>>>traffic>>>downlink"
    value: 67890
>
stat: <
    name: "inbound>>>socks-in>>>traffic>>>uplink"
    value: 100
>
"#;

    const SAMPLE_JSON: &str = r#"{
        "stat": [
            {"name": "outbound>>>proxy>>>traffic>>>downlink", "value": 67890},
            {"name": "outbound>>>proxy>>>traffic>>>uplink", "value": 12345},
            {"name": "outbound>>>direct>>>traffic>>>uplink"}
        ]
    }"#;

    #[test]
    fn parses_proto_text_format() {
        let s = StatsClient::parse_stats_query(SAMPLE_PROTO);
        assert!(s.available);
        assert_eq!(s.uplink_bytes, 12345);
        assert_eq!(s.downlink_bytes, 67890);
    }

    #[test]
    fn parses_json_format() {
        let s = StatsClient::parse_stats_query(SAMPLE_JSON);
        assert!(s.available);
        assert_eq!(s.uplink_bytes, 12345);
        assert_eq!(s.downlink_bytes, 67890);
    }

    #[test]
    fn json_with_missing_value_treats_as_zero() {
        let body = r#"{"stat":[{"name":"outbound>>>proxy>>>traffic>>>uplink"}]}"#;
        let s = StatsClient::parse_stats_query(body);
        assert!(s.available);
        assert_eq!(s.uplink_bytes, 0);
        assert_eq!(s.downlink_bytes, 0);
    }

    #[test]
    fn unavailable_returns_zeros() {
        let s = StatsClient::unavailable();
        assert!(!s.available);
        assert_eq!(s.uplink_bytes, 0);
        assert_eq!(s.downlink_bytes, 0);
    }
}
