//! Stats API client. xray-core exposes a gRPC StatsService; the easiest way
//! to read it from Rust without adding tonic + the .proto is to shell out
//! to `xray api statsquery -server 127.0.0.1:<stats_port> -pattern user>>>`
//! and parse the text response.
//!
//! Phase 2 ships the API surface and a parser for the text format; the real
//! shell-out is wired in Phase 2.5 once we have a bundled `xray` binary the
//! supervisor can invoke. Until then `traffic_stats` returns
//! `available: false`, which is the correct status when no stats source is
//! reachable (DEVELOPMENT.md §12 rule 6 keeps the listener loopback-only).

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

    /// Parse the text body returned by `xray api statsquery`. Format is a
    /// list of `Stat name: <name> value: <value>` blocks. We extract the
    /// `outbound>>>proxy>>>traffic>>>uplink` and `...>>>downlink` counters.
    pub fn parse_stats_query(body: &str) -> TrafficStats {
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
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    const SAMPLE: &str = r#"
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

    #[test]
    fn parses_known_format() {
        let s = StatsClient::parse_stats_query(SAMPLE);
        assert!(s.available);
        assert_eq!(s.uplink_bytes, 12345);
        assert_eq!(s.downlink_bytes, 67890);
    }

    #[test]
    fn unavailable_returns_zeros() {
        let s = StatsClient::unavailable();
        assert!(!s.available);
        assert_eq!(s.uplink_bytes, 0);
        assert_eq!(s.downlink_bytes, 0);
    }
}
