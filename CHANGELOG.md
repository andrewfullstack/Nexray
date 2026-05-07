# Changelog

All notable changes to Nexray are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Phase 0 foundation: repo skeleton, Zod profile schemas, vless:// codec,
  subscription parser/classifier, test corpus, fetch-core + gen-rust-types
  scripts, CI workflow, doc stubs.
- Phase 1 CLI: Cargo workspace with `nexray-core` (pure parser, behavioural
  parity with the TS reference) and `nexray-cli` (`classify <url-or-path>`
  with `--json`, HTTPS-only fetcher, redirect cap, rustls TLS). Vitest
  harness validates `--json` output against `ClassifyResultSchema` to prove
  Rust ↔ TS contract.
- Phase 2 Tauri shell + xray sidecar lifecycle:
  - Profile → Xray JSON materializer in `nexray-core::xray_config` with
    SOCKS inbound, default routing/DNS per §6.1, and an opt-in Stats API
    inbound bound to `127.0.0.1:<random>` (§12 rule 6).
  - `XraySidecar` FSM in `src-tauri/src/core.rs` with `Disconnected →
    Connecting → Connected | Crashed` transitions and an external-kill
    detection budget under 2s; never auto-restarts.
  - IPC commands `connect / disconnect / status / traffic_stats` typed via
    new Zod schemas in `src/lib/ipc.ts` (mirrored to Rust by the manifest).
  - System tray (Connect / Disconnect / Quit) per §13 lean.
  - macOS hardened-runtime entitlements stub, Windows app manifest,
    Linux .desktop bundling config.
  - `xray-stub` test binary + 4 lifecycle integration tests + 9 materializer
    tests + 2 stats parser tests.
- Phase 3 minimal UI:
  - React 18 + TypeScript shell with `react-router-dom` + `react-intl`.
  - Pages: `Home` (status pill, big Connect/Disconnect, live byte counters
    + sparkline) and `ProfileEditor` (paste vless:// link with inline Zod
    validation; structured field preview).
  - Zustand stores: `useProfileStore` (hydrated from `tauri-plugin-store`),
    `useConnectionStore` (1Hz polling of `status` + `traffic_stats`).
  - Typed Tauri IPC client (`src/lib/tauri.ts`) parses every response
    through Zod — wire-format mismatches surface with field name + reason.
  - Tray clicks (`tray-click` event) navigate to the connection page.
  - Dark-mode default theme; minimal CSS, no design system dep.

- Phase 4 subscriptions + server pool:
  - HTTPS-only fetcher (`reqwest`, rustls, 10s timeout, ≤3 redirects).
  - In-memory subscription map keyed by stable URL hash; persisted via
    `tauri-plugin-store` to `subscriptions.json`. Failed refresh keeps
    serving cached profiles per §5.4.
  - TCP-connect latency probe with 2s timeout and bounded concurrency
    (8 simultaneous probes).
  - Auto-refresh scheduler (60s tick, 6h default interval per §5.4).
  - IPC commands: `subscriptions_list / _add / _delete / _refresh`,
    `pool_list`, `pool_probe_all`.
  - UI pages: `Subscriptions` (add form with HTTPS rejection, accept/skip
    counts, per-sub refresh + delete) and `Pool` (sortable table by ping,
    "Probe latency" button, "Use" button to set active profile).
  - 4 new Rust unit tests (subscription id stability, HTTPS validation,
    refresh-due timing, TCP probe success + timeout against local listener).
  - §13 server-pool decision recorded.

- Phase 5 routing UI + presets + DNS:
  - Three routing presets (`default` / `direct` / `global`) materialised by
    `nexray_core::xray_config::routing_rules_for`.
  - User custom rules with `(domain | ip | port | network)` matcher types,
    `(direct | proxy | block)` destinations, and an `enabled` checkbox.
    Rules are prepended to the preset's so user intent always wins (Xray's
    first-match-wins).
  - DNS overrides under "Advanced": user-configurable domestic + proxy
    resolvers; system DNS leaks remain blocked unconditionally per §6.1.
  - Routing settings persisted via `tauri-plugin-store` to `routing.json`
    and threaded into every `connect` call.
  - `fetch-core.mjs` now also pulls geoip.dat + geosite.dat (SHA-256 pinned;
    placeholder hashes until the Phase-7 release pinning).
  - 5 new materializer tests (each preset shape, custom-rule prepending,
    disabled-rule skipping, DNS override propagation).

- Phase 6 TUN mode (FSM + UI; real packet capture pending privilege flow):
  - `TunSupervisor` lifecycle FSM in `src-tauri/src/tun.rs` mirroring the
    `XraySidecar` shape: `disabled → starting → active | failed`. Spawns the
    bundled `tun2socks` pointed at the SOCKS inbound; stderr line-streamed
    via tracing; Drop kills the child.
  - IPC: `tun_capabilities` (platform + binary present probe),
    `tun_status` / `tun_enable` / `tun_disable`. Lives alongside the
    existing connect/disconnect commands.
  - Home page TUN toggle with status pill, busy state, last-error surface,
    and a tooltip explaining UAC / sudo / CAP_NET_ADMIN requirements per OS.
  - `fetch-core.mjs` extended with `TUN2SOCKS` map (xjasonlyu/tun2socks
    v2.5.2) per arch with SHA-256 placeholders.
  - 4 new lifecycle integration tests against `xray-stub`.
  - §13 question 1 (own tun2socks build) decided as `xjasonlyu/tun2socks`.

- Phase 7 polish + release scaffolding:
  - Settings page with auto-update opt-in toggle (default off) and
    telemetry opt-in toggle (default off; not implemented even when
    enabled, kept visible so any future opt-in is auditable).
  - About page with name / version / license / platform and live SHA-256
    of the bundled `xray-core` + `tun2socks` binaries (computed via a tiny
    in-tree streaming SHA-256 — no extra dep).
  - `tauri-plugin-updater` registered with placeholder pubkey + endpoint
    in `tauri.conf.json`; capabilities granted. Real keys land with the
    first signed release.
  - `.github/workflows/release.yml` — tag-driven matrix build on macOS-14
    (arm64 + x64), ubuntu-22.04, windows-latest. Wires Tauri signing,
    Apple notarization, and Windows code-signing through Actions secrets;
    refuses to download bundled binaries if SHA-256 entries are still
    placeholders. Drops a draft GitHub Release on completion.
  - Self-heal: PID files at `<app-data>/runtime/{xray,tun2socks}.pid`
    written on supervisor start, removed on stop/Drop. Boot-time
    `runtime::scrub_orphans` kills survivors and removes stale files so
    a force-kill of the app doesn't leak proxy children.
  - Updater capability + plugin handler ready to call from JS once the
    pubkey is provisioned.

### Open / deferred (operational, no code blockers)
- Real SHA-256 hashes in `scripts/fetch-core.mjs` for `xray-core`,
  `tun2socks`, `geoip.dat`, `geosite.dat`. Without these, fetch-core
  refuses to download — by design.
- Apple Developer ID / Apple ID app-specific password / Windows EV (or
  Azure Trusted Signing) certs uploaded as Actions secrets per
  `.github/workflows/release.yml` comments.
- Tauri updater public-key + endpoint URL substituted into
  `src-tauri/tauri.conf.json` (currently `REPLACE_ME_*` placeholders).
- §12 rule 2 (Keychain / DPAPI / libsecret encryption-at-rest for profile
  secrets) — Phase 7.5 once a Stronghold or `keyring`-crate integration
  story is decided. Tracked in `docs/SECURITY.md`.
- macOS SMJobBless / Windows UAC helper for TUN packet capture — Phase 7.5
  alongside code-signing. Phase 6 surfaces failures with `state: failed`
  + a clear "needs admin" `lastError`.
