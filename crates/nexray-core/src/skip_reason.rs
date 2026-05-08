//! Mirror of `SKIP_REASONS` in `src/lib/profile.ts`. The string values are the
//! contract — every variant serializes to the same string the TS classifier
//! emits, so a JSON `{ raw, reason }` is byte-identical across both sides.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SkipReason {
    #[serde(rename = "shadowsocks (legacy)")]
    ShadowsocksLegacy,
    // Plain `trojan://` over TCP+TLS is supported and parses to a Profile.
    // trojan-go is a separate, incompatible fork — still rejected.
    #[serde(rename = "trojan-go (legacy)")]
    TrojanGoLegacy,
    #[serde(rename = "trojan+ws (unsupported)")]
    TrojanWs,
    // Plain `vmess://` over TCP+TLS+AEAD is supported and parses to a Profile.
    // The WebSocket variant is rejected because Phase-7 scope is TCP+TLS only.
    #[serde(rename = "vmess+ws (unsupported)")]
    VmessWs,
    #[serde(rename = "http (unsupported as outbound)")]
    HttpUnsupported,
    #[serde(rename = "socks (unsupported as outbound)")]
    SocksUnsupported,
    #[serde(rename = "reality+ws (invalid combination)")]
    RealityWs,
    #[serde(rename = "reality+grpc (invalid combination)")]
    RealityGrpc,
    #[serde(rename = "reality+xhttp (invalid combination)")]
    RealityXhttp,
    #[serde(rename = "reality+httpupgrade (invalid combination)")]
    RealityHttpUpgrade,
    #[serde(rename = "vless+tls direct (use reality instead)")]
    VlessTlsDirect,
    #[serde(rename = "vless+kcp (mKCP unsupported)")]
    VlessKcp,
    #[serde(rename = "vless+quic (raw QUIC inbound unsupported)")]
    VlessQuic,
    #[serde(rename = "malformed")]
    Malformed,
    #[serde(rename = "unknown protocol")]
    UnknownProtocol,
}

impl SkipReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShadowsocksLegacy => "shadowsocks (legacy)",
            Self::TrojanGoLegacy => "trojan-go (legacy)",
            Self::TrojanWs => "trojan+ws (unsupported)",
            Self::VmessWs => "vmess+ws (unsupported)",
            Self::HttpUnsupported => "http (unsupported as outbound)",
            Self::SocksUnsupported => "socks (unsupported as outbound)",
            Self::RealityWs => "reality+ws (invalid combination)",
            Self::RealityGrpc => "reality+grpc (invalid combination)",
            Self::RealityXhttp => "reality+xhttp (invalid combination)",
            Self::RealityHttpUpgrade => "reality+httpupgrade (invalid combination)",
            Self::VlessTlsDirect => "vless+tls direct (use reality instead)",
            Self::VlessKcp => "vless+kcp (mKCP unsupported)",
            Self::VlessQuic => "vless+quic (raw QUIC inbound unsupported)",
            Self::Malformed => "malformed",
            Self::UnknownProtocol => "unknown protocol",
        }
    }
}

impl core::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
