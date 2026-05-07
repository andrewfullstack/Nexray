# Security

This document enumerates every non-negotiable security rule from
[`DEVELOPMENT.md` §12](../DEVELOPMENT.md) and points to the test or runtime
check that enforces it. A rule without an enforcer is a TODO that must close
before the gating phase ships.

## Threat model summary

Nexray runs on a user's desktop and forwards arbitrary user traffic to
remote servers chosen by the user. The hostile parties we model:

- **The local network** (ISP / Wi-Fi / state-level censor): can fingerprint
  TLS, do active probing, and block IPs. Defenses: REALITY borrowed SNI,
  uTLS fingerprint, CDN fronting (cdn-ws).
- **A malicious or compromised subscription provider**: can ship malformed
  links, attempt to silently downgrade us to a legacy protocol, or smuggle
  `allowInsecure: true`. Defenses: schema rejection at parse time, no silent
  defaults that change semantics, logging redaction.
- **A local attacker on the same machine**: can probe localhost ports.
  Defenses: Stats API bound to `127.0.0.1:<random>`, never exposed.

## Non-negotiable rules

| # | Rule | Enforcer |
|---|------|----------|
| 1 | Subscription fetch over HTTPS only. Reject `http://` URLs at parse time. | _Phase 1: subscription fetcher in `src-tauri/src/subscription.rs` + integration test._ |
| 2 | Never persist subscription credentials in plain text. macOS: Keychain. Windows: DPAPI. Linux: libsecret. | **Open — Phase 7.** Phase 3 uses `tauri-plugin-store` which writes a plain JSON file under the OS app-data directory; UUIDs and public keys are stored as plaintext. Phase 7 will move secret fields into the OS keyring (`keyring` crate or `tauri-plugin-stronghold`). Tracked in `CHANGELOG.md`. |
| 3 | Validate `fingerprint` against the whitelist. Unknown ⇒ hard failure. | `tests/profile.test.ts` ("rejects unknown fingerprint"); `tests/share-link.test.ts` (`MALFORMED_BAD_FP`). |
| 4 | Refuse to materialize an Xray config if any mandatory field is missing — fail loudly with a structured error. | _Phase 2: materializer in `src-tauri/src/config.rs` + unit test._ |
| 5 | No telemetry. No crash reporting that ships data off-device by default. | Manual review per PR. About-page UI in Phase 7 surfaces the off state. |
| 6 | Stats API bound to `127.0.0.1:<random>`, never exposed. | _Phase 2: startup assertion in `src-tauri/src/stats.rs` that the bind addr is loopback; fails closed._ |
| 7 | Bundled xray-core SHA-256 pinned. CI verifies. Never auto-upgrade. | `scripts/fetch-core.mjs` HASHES table; download refused if SHA mismatches; CI runs `pnpm fetch-core` for the matrix. |

## Logging redaction

Per [`DEVELOPMENT.md` §11](../DEVELOPMENT.md): UUIDs, public keys, short IDs,
and full subscription URLs must be redacted **at the formatter, not the call
site**. Phase 2+ adds `tracing` middleware and a `consola` formatter that
substitute these patterns with `***` before emit. Each logger has a unit test
that scans output for the redaction patterns.

## What is not in this document

Per-phase mitigations land in this file as their phase ships. The threat
model itself will be expanded in Phase 7 after the first external review.
