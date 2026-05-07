# Nexray

A minimal, modern VLESS proxy client. Two deployment profiles, nothing else.

| Profile | Stack | Use case |
|---------|-------|----------|
| `cdn-ws` | VLESS + WebSocket + TLS, fronted by a CDN | Free / anti-IP-block tier |
| `reality` | VLESS + Vision flow + REALITY over raw TCP | Paid VPS; lowest latency |

By design, Nexray refuses VMess, Shadowsocks, Trojan, and every other legacy
or insecure-by-default combination. See [`DEVELOPMENT.md`](./DEVELOPMENT.md)
for the full vision and non-goals.

## Status

Phase 7 — feature-complete, awaiting first signed release. All eight roadmap
phases (foundation → CLI → Tauri shell → UI → subscriptions → routing → TUN
→ release scaffolding) are implemented. The remaining work is operational:
populating SHA-256 hashes for bundled binaries, code-signing setup, and
notarization. See [`CHANGELOG.md`](./CHANGELOG.md).

## Build & test

```bash
pnpm install
pnpm test                              # vitest (incl. CLI ↔ Zod harness)
pnpm typecheck && pnpm lint
cargo test --workspace --all-targets   # core + CLI + lifecycle + materializer
cargo clippy --workspace -- -D warnings
```

## Run the desktop app (development)

```bash
pnpm tauri dev
```

> The desktop app needs the bundled `xray-core` and `tun2socks` binaries to
> actually proxy traffic. Until the SHA-256 entries in
> [`scripts/fetch-core.mjs`](./scripts/fetch-core.mjs) are populated, the
> Connect / TUN buttons will surface a "binary not bundled" error. The UI,
> subscription manager, and routing pages still work in this dev mode.

## CLI usage (`nexray-cli`)

```bash
# Classify a local file (one share-link per line, plain or base64-wrapped).
cargo run --quiet -p nexray-cli -- classify ./subscription.txt

# Read from stdin.
cat sub.txt | cargo run --quiet -p nexray-cli -- classify -

# Fetch over HTTPS (plain http:// is rejected).
cargo run --quiet -p nexray-cli -- classify https://your-airport.example/sub

# Machine-readable output (validates against the Phase-0 Zod schemas).
cargo run --quiet -p nexray-cli -- classify ./subscription.txt --json
```

The classifier accepts only `cdn-ws` (VLESS+WS+TLS) and `reality`
(VLESS+Vision+REALITY). Every other share-link format — VMess, Shadowsocks,
Trojan, REALITY+gRPC/WS, plain VLESS+TLS direct — is reported in the
"servers skipped" summary line per [`DEVELOPMENT.md` §5.3](./DEVELOPMENT.md).

## Security notes

Highlights from [`docs/SECURITY.md`](./docs/SECURITY.md) (full threat model
and per-rule enforcement):

- Subscription fetches are HTTPS-only; `http://` URLs are rejected at parse
  time.
- The Stats API listener is bound to `127.0.0.1:<random>`, never exposed.
- Profile schemas reject `allowInsecure: true`; the Xray config materializer
  always emits `allowInsecure: false` regardless of input.
- Fingerprints, flows, REALITY public keys, and short IDs are all whitelist-
  validated; unknown values are hard failures, not silent fallbacks.
- xray-core, tun2socks, geoip.dat, and geosite.dat are SHA-256 pinned in
  `scripts/fetch-core.mjs`. Fetching refuses to run if hashes drift, and the
  binaries are never auto-upgraded across releases.
- No telemetry. The Settings page exposes a telemetry toggle that currently
  does nothing — kept visible so a future opt-in is auditable.

## Project layout

This is a Cargo workspace + pnpm root.

```
nexray/
├── crates/
│   ├── nexray-core/       # pure-Rust parser + types + xray config materializer
│   ├── nexray-cli/        # `nexray-cli classify` binary
│   └── xray-stub/         # test-only sidecar imposter for lifecycle tests
├── src-tauri/             # Tauri shell (xray supervisor, TUN, IPC, tray, …)
├── src/                   # React UI
├── scripts/               # fetch-core.mjs, gen-rust-types.mjs, …
└── tests/                 # vitest suite
```

## License

GPL-3.0 — see [`LICENSE`](./LICENSE).
