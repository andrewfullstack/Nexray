//! Pure-Rust mirror of the TypeScript parser in `src/lib/*.ts`.
//!
//! `nexray-core` has no IO. Network fetches happen in `nexray-cli` (blocking
//! reqwest) or in the Tauri shell (async tokio). The schema mirror in
//! `types_generated.rs` is auto-generated from the Zod schemas via
//! `scripts/gen-rust-types.mjs` — never edit it by hand.

pub mod errors;
pub mod rules_conf;
pub mod share_link;
pub mod skip_reason;
pub mod subscription;
pub mod xray_config;

#[path = "types_generated.rs"]
mod types_gen;

pub use share_link::{decode_share_link, encode_share_link, DecodeResult};
pub use skip_reason::SkipReason;
pub use subscription::{classify_subscription, summarize_skipped, ClassifyResult, SkippedEntry};
pub use types_gen::{
    AddSubscriptionRequest, Alpn, AppInfo, AppSettings, CdnWsProfile, ConnectRequest,
    ConnectionState, ConnectionStatus, CustomRule, DnsConfig, Fingerprint, Profile, RealityProfile,
    RoutingDestination, RoutingMatcherType, RoutingPreset, RoutingSettings, SetRoutingRequest,
    SetSettingsRequest, Subscription, SubscriptionIdRequest, SystemProxyStatus, TrafficStats,
    TunCapabilities, TunState, TunStatus,
};

/// Whitelist of uTLS fingerprints accepted by the parser. Mirrors
/// `FINGERPRINTS` in `src/lib/profile.ts`. Unknown values are a hard failure
/// per DEVELOPMENT.md §4.2 / §12 rule 3.
pub const FINGERPRINTS: &[(Fingerprint, &str)] = &[
    (Fingerprint::Chrome, "chrome"),
    (Fingerprint::Firefox, "firefox"),
    (Fingerprint::Safari, "safari"),
    (Fingerprint::Ios, "ios"),
    (Fingerprint::Android, "android"),
    (Fingerprint::Edge, "edge"),
    (Fingerprint::Random, "random"),
];
