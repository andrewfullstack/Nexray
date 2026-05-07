//! Subscription manager — Phase 4.
//!
//! Holds the in-memory subscription map, fetches remote bodies over HTTPS
//! (DEVELOPMENT.md §12 rule 1), classifies entries with `nexray-core`, and
//! persists state via `tauri-plugin-store`. The auto-refresh scheduler in
//! `lib.rs` calls `refresh_due` periodically; the IPC commands call `add`,
//! `delete`, and `refresh` on user action.
//!
//! Latency probe is a TCP connect-time measurement against
//! `address:port`. We never proxy the probe — it's local — so the user's
//! ISP sees a small TCP connect to the server. Acceptable trade-off for
//! "smart select"; document if anyone asks.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nexray_core::{
    classify_subscription, summarize_skipped, AddSubscriptionRequest, Profile, Subscription,
};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::time::timeout;
use url::Url;

/// Default refresh cadence (DEVELOPMENT.md §5.4: "user-configurable, default 6h").
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// HTTPS request timeout (10s — same as nexray-cli).
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-server TCP-connect probe timeout.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Bound on concurrent probes so we don't open hundreds of sockets at once.
pub const PROBE_CONCURRENCY: usize = 8;

const USER_AGENT: &str = concat!("Nexray/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("subscription URL must be HTTPS")]
    NotHttps,
    #[error("invalid subscription URL: {0}")]
    InvalidUrl(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("{0}")]
    NotASubscription(String),
}

/// True when the response looks like an HTML / web page rather than a
/// subscription body. Catches the most common "wrong URL / wrong token"
/// case where the origin's default page (nginx welcome, framework 404,
/// SPA shell) is returned with a 200 status. We sniff the content-type
/// header first; some misconfigured servers send `text/plain` or no
/// content-type at all, so we also peek at the first bytes of the body.
fn looks_like_html(content_type: &str, body: &str) -> bool {
    if content_type.contains("text/html") || content_type.contains("application/xhtml") {
        return true;
    }
    let head = body.trim_start();
    if head.is_empty() {
        return false;
    }
    let head_lower = head[..head.len().min(64)].to_ascii_lowercase();
    head_lower.starts_with("<!doctype")
        || head_lower.starts_with("<html")
        || head_lower.starts_with("<head")
        || head_lower.starts_with("<?xml")
}

#[derive(Default)]
pub struct ProbeRecord {
    pub latency_ms: Option<u32>,
    pub last_probe_ms: Option<u64>,
}

/// Build the canonical id for a subscription. Stable across re-adds — if the
/// same URL is added twice we want to surface "already exists" not duplicate.
pub fn subscription_id(url: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in url.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("sub-{h:016x}")
}

fn default_name_from_url(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| "subscription".to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Fetch a subscription URL, classify the body, and produce a fresh
/// `Subscription` record. Caller decides whether to persist it. Returns
/// `Err` only on hard failures — an HTTPS-rejected URL or a network error
/// surfaces as `Err`. The caller may keep stale `profiles` from a prior
/// successful fetch on failure.
pub async fn fetch_and_classify(
    id: &str,
    url: &str,
    name: &str,
    added_ms: u64,
) -> Result<Subscription, FetchError> {
    nexray_core::subscription::require_https(url).map_err(|_| FetchError::NotHttps)?;

    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(3))
        .https_only(true)
        .build()
        .map_err(|e| FetchError::Http(e.to_string()))?;

    let resp = client
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| FetchError::Http(e.to_string()))?;
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let body = resp
        .text()
        .await
        .map_err(|e| FetchError::Http(e.to_string()))?;

    // Sanity check: many "wrong URL / wrong token" cases land on the
    // origin's default page (nginx welcome, JSON 404, etc.). Detect
    // HTML so the user gets a useful error instead of "23 servers
    // skipped: 23 unknown protocol" from each HTML line being run
    // through the share-link parser.
    if looks_like_html(&content_type, &body) {
        return Err(FetchError::NotASubscription(
            "endpoint returned HTML, not a subscription body — check the URL or token".into(),
        ));
    }

    let result = classify_subscription(&body);
    let summary = if result.skipped.is_empty() {
        None
    } else {
        Some(summarize_skipped(&result.skipped))
    };

    Ok(Subscription {
        id: id.to_string(),
        url: url.to_string(),
        name: name.to_string(),
        added_ms,
        last_fetched_ms: Some(now_ms()),
        last_fetch_error: None,
        accepted_count: result.accepted.len() as u32,
        skipped_count: result.skipped.len() as u32,
        skipped_summary: summary,
        profiles: result.accepted,
    })
}

/// Build a sentinel record used right after a user adds a URL; immediately
/// followed by `fetch_and_classify` to populate the real fields.
pub fn pending(url: &str, name_override: Option<&str>) -> Subscription {
    let id = subscription_id(url);
    let name = name_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| default_name_from_url(url));
    Subscription {
        id,
        url: url.to_string(),
        name,
        added_ms: now_ms(),
        last_fetched_ms: None,
        last_fetch_error: None,
        accepted_count: 0,
        skipped_count: 0,
        skipped_summary: None,
        profiles: vec![],
    }
}

/// Validate `add` request before any I/O. Used by both the IPC command and the
/// auto-refresh scheduler so behaviour is identical.
pub fn validate_add(req: &AddSubscriptionRequest) -> Result<(), FetchError> {
    let url = req.url.trim();
    if url.is_empty() {
        return Err(FetchError::InvalidUrl("empty".into()));
    }
    nexray_core::subscription::require_https(url).map_err(|_| FetchError::NotHttps)?;
    Url::parse(url).map_err(|e| FetchError::InvalidUrl(e.to_string()))?;
    Ok(())
}

/// Tracker for `is_due_for_refresh(now, last, interval)`. Pure helper so the
/// scheduler can be unit-tested without sleeping.
pub fn is_due(now_ms: u64, last_fetched_ms: Option<u64>, interval: Duration) -> bool {
    match last_fetched_ms {
        None => true,
        Some(last) => now_ms.saturating_sub(last) >= interval.as_millis() as u64,
    }
}

pub fn profile_id(p: &Profile) -> &str {
    match p {
        Profile::CdnWs(p) => &p.id,
        Profile::Reality(p) => &p.id,
    }
}

fn profile_endpoint(p: &Profile) -> (String, u16) {
    match p {
        Profile::CdnWs(p) => (p.address.clone(), p.port),
        Profile::Reality(p) => (p.address.clone(), p.port),
    }
}

/// Probe a single profile by TCP-connecting to its `address:port`. Returns
/// `None` on timeout or DNS failure. Latency is wall-clock from `connect()`
/// call to ready, in milliseconds.
pub async fn probe_one(profile: &Profile) -> Option<u32> {
    let (host, port) = profile_endpoint(profile);
    let addr = format!("{host}:{port}");
    let start = Instant::now();
    match timeout(PROBE_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => Some(start.elapsed().as_millis() as u32),
        _ => None,
    }
}

/// Probe every profile across every subscription, with bounded concurrency.
/// Returns a vec of `(profile_id, latency_ms_option)`.
pub async fn probe_all(profiles: &[Profile]) -> Vec<(String, Option<u32>)> {
    use tokio::sync::Semaphore;
    let sem = std::sync::Arc::new(Semaphore::new(PROBE_CONCURRENCY));
    let mut handles = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let id = profile_id(profile).to_string();
        let p = profile.clone();
        let sem = std::sync::Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            Some((id, probe_one(&p).await))
        }));
    }
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(Some(pair)) = h.await {
            out.push(pair);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

    #[test]
    fn html_detector_catches_common_default_pages() {
        // nginx default page (real-world repro from a misconfigured CDN
        // proxy that returns the origin's nginx welcome at the
        // subscription path).
        let nginx = "<!DOCTYPE html>\n<html>\n<head><title>Welcome to nginx!</title>";
        assert!(looks_like_html("text/html; charset=utf-8", nginx));
        assert!(looks_like_html("", nginx));

        // Lowercase + leading whitespace is still HTML.
        assert!(looks_like_html("", "  \n\t<HTML>"));

        // SPA / framework HTML.
        assert!(looks_like_html(
            "text/html",
            "<html><body>hello</body></html>"
        ));

        // Real subscription bodies must NOT match. Plain vless://, base64,
        // and an empty body all pass through.
        assert!(!looks_like_html(
            "text/plain",
            "vless://uuid@host:443?type=ws"
        ));
        assert!(!looks_like_html(
            "application/octet-stream",
            "dmxlc3M6Ly9hYWFhQGZvbzo0NDM/dHlwZT13cw=="
        ));
        assert!(!looks_like_html("", ""));
    }

    #[test]
    fn id_is_stable() {
        assert_eq!(
            subscription_id("https://example.com/sub"),
            subscription_id("https://example.com/sub")
        );
        assert_ne!(
            subscription_id("https://example.com/sub"),
            subscription_id("https://example.com/sub/2")
        );
    }

    #[test]
    fn validate_add_rejects_http() {
        let r = validate_add(&AddSubscriptionRequest {
            url: "http://example.com/sub".into(),
            name: None,
        });
        assert!(matches!(r, Err(FetchError::NotHttps)));
    }

    #[test]
    fn is_due_handles_first_run_and_interval() {
        // Never fetched: always due.
        assert!(is_due(1_000_000, None, Duration::from_secs(60)));
        // Fetched 30s ago, 60s interval: not yet due.
        assert!(!is_due(60_000, Some(30_000), Duration::from_secs(60)));
        // Fetched 90s ago, 60s interval: due.
        assert!(is_due(90_000, Some(0), Duration::from_secs(60)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn probe_one_succeeds_against_local_listener() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let profile = Profile::CdnWs(nexray_core::CdnWsProfile {
            id: "p1".into(),
            name: "p1".into(),
            remark: None,
            address: "127.0.0.1".into(),
            port,
            uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
            host: "h".into(),
            path: "/".into(),
            sni: "h".into(),
            alpn: vec![nexray_core::Alpn::H2],
            fingerprint: nexray_core::Fingerprint::Chrome,
        });
        let latency = probe_one(&profile).await;
        assert!(latency.is_some(), "expected a measurement");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn probe_one_times_out_against_dead_port() {
        // Bind, then drop, so the port is reusable but probably not listening.
        // Use 127.0.0.1:1 which is reserved-ish on Unix; connect refused fast.
        let profile = Profile::CdnWs(nexray_core::CdnWsProfile {
            id: "p1".into(),
            name: "p1".into(),
            remark: None,
            address: "127.0.0.1".into(),
            port: 1,
            uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
            host: "h".into(),
            path: "/".into(),
            sni: "h".into(),
            alpn: vec![nexray_core::Alpn::H2],
            fingerprint: nexray_core::Fingerprint::Chrome,
        });
        let latency = probe_one(&profile).await;
        // Either None (refused/timeout) — not Some(_).
        assert!(latency.is_none());
    }
}
