# Architecture

This document records the system architecture of Nexray and the resolved
answers to the open design questions in [`DEVELOPMENT.md` §13](../DEVELOPMENT.md).
**Each question MUST be answered before its gating phase begins.**

## Layered overview

```
+-------------------------------------------------+
|  UI  (React + TypeScript + Vite)                |
+----------------------+--------------------------+
                       | Tauri IPC (typed)
+----------------------+--------------------------+
|  Shell  (Rust, Tauri 2)                         |
+----------------------+--------------------------+
                       | stdin / Stats API (gRPC, 127.0.0.1)
+----------------------+--------------------------+
|  xray-core  (sidecar binary, bundled)           |
+-------------------------------------------------+
```

All Xray config materialization, validation, and process management happens in
the Rust shell. The UI never touches xray-core directly.

## §13 open questions — resolution log

| # | Question | Decision | Date | Notes |
|---|----------|----------|------|-------|
| 1 | TUN library: own `tun2socks` build vs `sing-tun`? | **decided — `xjasonlyu/tun2socks`** | Phase 6 | We bundle pinned `tun2socks` binaries per arch (SHA-256 verified) rather than building our own or pulling sing-tun via FFI. xjasonlyu/tun2socks already supports utun (macOS) / wintun (Windows) / `/dev/net/tun` (Linux) and ships a stable CLI surface. Privilege escalation (SMJobBless / UAC helper) is a separate Phase 7 polish item — Phase 6 surfaces "needs admin" failures explicitly. |
| 2 | Single-server vs server pool with latency selection? | **decided — pool from Phase 4** | Phase 4 | Pool view aggregates profiles across all subscriptions; user-driven "Probe latency" button populates ping data; sort-by-ping default. Auto-switch on refresh ("smart select") deferred to Phase 5+. |
| 3 | Tray icon? | **decided — yes** | Phase 2 | Tray installed via `tauri::tray::TrayIconBuilder` with Connect / Disconnect / Quit menu. Connect/Disconnect emit `tray-click` events the React UI subscribes to. |
| 4 | Auto-update mechanism? | _pending — Phase 7_ | — | Lean: Tauri updater behind opt-in toggle. |

When a decision lands, replace `_pending_` with `decided` and record the
deciding PR + rationale in the Notes column.

## Phase 1 deviation: Cargo workspace

DEVELOPMENT.md §8 lists `src-tauri/src/bin/nexray-cli.rs` for the Phase 1
CLI. We deviated from this in Phase 1: putting the CLI inside `src-tauri`'s
crate would force every CLI invocation to build the full Tauri / Wry /
WebView2 dependency tree.

**Decision (Phase 1):** convert the repo to a Cargo workspace with three
members:

- `crates/nexray-core` — pure-Rust parser + types. No IO. No Tauri. Used by
  both the CLI and the shell.
- `crates/nexray-cli` — the `nexray-cli` binary. Depends on `nexray-core` +
  `clap` + `reqwest` (rustls, blocking). Compiles in seconds, ships as a
  standalone binary.
- `src-tauri` — the Tauri shell. Depends on `nexray-core` for the parser.

The TypeScript Zod schemas remain the single source of truth; the Rust
mirror lives in `crates/nexray-core/src/types_generated.rs` (auto-generated
from `scripts/gen-rust-types.mjs`, CI-checked via `pnpm verify-types`).

**Why deviate:** a CLI tool has no business pulling in WebView2 /
libwebkit2gtk. The split also makes it trivial to publish `nexray-cli`
standalone later if anyone wants a headless classifier.

## Sequence flows

### Connect

```
UI                Shell                  xray-core            net
 |  invoke connect |                         |                  |
 | (profile_id) →  |                         |                  |
 |                 | load profile from store |                  |
 |                 | materialize XrayConfig  |                  |
 |                 | spawn sidecar (stdin)→  |                  |
 |                 |                         | listen 127.0.0.1 |
 |                 | start StatsAPI client → |                  |
 |   ← Connected   |                         |                  |
```

### Subscription refresh

```
UI                Shell                external sub URL
 |   trigger →     |                         |
 |                 | HTTPS GET (10s)    →    |
 |                 |  ← body                 |
 |                 | base64-detect           |
 |                 | per-line decodeShareLink|
 |                 | classify                |
 |                 | persist accepted        |
 |  ← {accepted,   |                         |
 |     skipped}    |                         |
```

### `nexray-cli classify` (Phase 1)

```
user        nexray-cli            external sub URL
 |  classify  |                         |
 | <src>  →   |                         |
 |            | source = URL?           |
 |            |   require_https()       |
 |            |   reqwest GET (10s) →   |
 |            |    ← body               |
 |            | source = file/stdin?    |
 |            |   read locally          |
 |            | classify_subscription() |
 |  ← table   |                         |
 |  ← --json  |                         |
```

(Detailed sequence diagrams for Phases 2+ will be added in their gating
phases.)

## Schema as source of truth

`src/lib/profile.ts` (Zod) is the contract. Rust types live in
`src-tauri/src/types.generated.rs`, generated by `scripts/gen-rust-types.mjs`
from a manifest that must match the schema. CI runs `pnpm verify-types` to
detect drift; a Zod field added without updating the manifest fails CI.
