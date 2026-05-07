# nexray — Development Guide

A minimal, modern VLESS client. Two deployment profiles, nothing else.

---

## 1. Vision & Scope

### 1.1 What we are building

A cross-platform proxy client that consumes airport (机场) subscriptions and connects through **exactly two** modern VLESS stacks:

| ID | Name | Stack | Use case |
|----|------|-------|----------|
| `cdn-ws` | CDN WebSocket | VLESS + WebSocket + TLS, fronted by a CDN (typically Cloudflare) | Free / anti-IP-block tier; latency-tolerant |
| `reality` | REALITY direct | VLESS + Vision flow + REALITY over raw TCP | Paid VPS; lowest latency; strongest anti-detection |

These are the two endpoints of the modern threat-model spectrum:

- `cdn-ws` wins on **anonymity, free hosting, IP-block resistance** (CF's IP pool is too costly to fully block).
- `reality` wins on **active-probe resistance, latency, fingerprint cleanliness** (REALITY borrows a real site's TLS handshake; Vision removes the TLS-in-TLS fingerprint).

### 1.2 Explicit non-goals

We do **not** support and will reject in code review:

- VMess (replaced by VLESS; legacy MD5/AEAD baggage)
- Shadowsocks, ShadowsocksR
- Trojan, Trojan-Go
- HTTP / SOCKS as outbound proxy protocols
- Any combination of REALITY with WS / gRPC / XHTTP transports (REALITY is TCP-only by design here)
- mKCP, raw QUIC inbound
- TLS without REALITY for direct-IP connections (use REALITY instead — there is no good reason in 2026 to ship a self-signed or LE-cert direct VLESS server)

Dropping legacy protocols is a feature: smaller binary, smaller config schema, smaller attack surface, and a UX that does not present users with options no one should be choosing.

---

## 2. Architecture

```
+-------------------------------------------------+
|  UI  (React + TypeScript + Vite)                |
|   - Subscription manager                        |
|   - Profile editor (cdn-ws / reality only)      |
|   - Routing rules                               |
|   - Connection status & traffic stats           |
+----------------------+--------------------------+
                       | Tauri IPC (typed commands)
+----------------------+--------------------------+
|  Shell  (Rust, Tauri 2)                         |
|   - Config persistence (Tauri Store)            |
|   - Subscription fetcher + parser               |
|   - Xray sidecar lifecycle (spawn / health)     |
|   - System proxy / TUN integration              |
|   - Stats poller (Xray Stats API)               |
+----------------------+--------------------------+
                       | stdin / unix socket / gRPC API
+----------------------+--------------------------+
|  xray-core  (sidecar binary, bundled)           |
+-------------------------------------------------+
```

The UI never touches xray-core directly. All config materialization, validation, and process management happens in the Rust shell. This keeps the React side stateless w.r.t. the proxy engine and makes it trivially swappable (e.g. to sing-box later).

---

## 3. Tech stack

| Layer | Choice | Why |
|-------|--------|-----|
| Proxy core | **xray-core** (sidecar) | Reference implementation for VLESS / Vision / REALITY; protocol authority |
| Shell | **Tauri 2** | Small bundle, native menus, OS integration, signed binaries |
| UI | **React 18 + TypeScript + Vite** | Standard, fast HMR, large ecosystem |
| State (UI) | **Zustand** | Minimal boilerplate, no Redux ceremony |
| Persistence | **Tauri Store** plugin | Encrypted-at-rest on macOS via Keychain integration |
| Schema | **Zod** | Single source of truth shared between UI and IPC boundary |
| Build | **pnpm + cargo** | Workspace-friendly |

Future drop-in alternatives:
- Core: sing-box (also implements VLESS+Vision+REALITY compatibly)
- Shell: Electron (only if Tauri proves limiting on Windows TUN integration)

---

## 4. Profile reference configs

These are the canonical Xray client outbounds the shell must produce. Validation must reject any profile that deviates from these shapes.

### 4.1 `cdn-ws`

```json
{
  "protocol": "vless",
  "settings": {
    "vnext": [{
      "address": "<cdn-edge-ip-or-host>",
      "port": 443,
      "users": [{
        "id": "<uuid>",
        "encryption": "none"
      }]
    }]
  },
  "streamSettings": {
    "network": "ws",
    "security": "tls",
    "tlsSettings": {
      "serverName": "<sni>",
      "alpn": ["h2", "http/1.1"],
      "fingerprint": "chrome",
      "allowInsecure": false
    },
    "wsSettings": {
      "path": "/?ed=2560",
      "headers": { "Host": "<host>" }
    }
  }
}
```

Notes:
- `address` is often a clean Cloudflare edge IP, **not** the apex domain. `host` and `serverName` carry the real domain.
- Always set uTLS `fingerprint: chrome` even with WS — it shapes the ClientHello.
- Reject `allowInsecure: true` from any subscription input.
- Path may include the early-data hint `?ed=2048` or higher; preserve it verbatim.

### 4.2 `reality`

```json
{
  "protocol": "vless",
  "settings": {
    "vnext": [{
      "address": "<server-ip>",
      "port": 443,
      "users": [{
        "id": "<uuid>",
        "flow": "xtls-rprx-vision",
        "encryption": "none"
      }]
    }]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "serverName": "<dest-sni, e.g. www.microsoft.com>",
      "fingerprint": "chrome",
      "publicKey": "<server-public-key>",
      "shortId": "<short-id>",
      "spiderX": ""
    }
  }
}
```

Hard validation rules:
- `flow` MUST equal `xtls-rprx-vision`.
- `network` MUST equal `tcp`. Reject any subscription that combines `security: reality` with `ws` / `grpc` / `xhttp` / `httpupgrade`.
- `fingerprint` defaults to `chrome`. Whitelist: `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `random`.
- `serverName` is the **borrowed** SNI of the dest the server steals TLS from (e.g. `www.microsoft.com`), not the proxy server's own domain.
- `publicKey` is base64url. `shortId` is hex (0–16 chars, even length).

---

## 5. Subscription handling

### 5.1 Accepted input formats

1. **VLESS share link**: `vless://<uuid>@<host>:<port>?<query>#<remark>`
2. **Base64 (URL-safe or standard) wrapping** of newline-separated share links — the most common 机场 default
3. **Plain newline-separated** share links

### 5.2 Required query keys per profile

`cdn-ws`:
- `type=ws`
- `security=tls`
- `host=<host>`
- `path=<path>` (URL-decoded)
- `sni=<sni>`
- `encryption=none`
- optional: `fp=<fingerprint>`, `alpn=<alpn>`

`reality`:
- `type=tcp`
- `security=reality`
- `pbk=<publicKey>`
- `sid=<shortId>`
- `fp=<fingerprint>`
- `sni=<dest-sni>`
- `flow=xtls-rprx-vision`
- `encryption=none`
- optional: `spx=<spiderX>`

### 5.3 Unsupported entries

When parsing, classify each entry as `cdn-ws`, `reality`, or `unsupported`. Skip `unsupported` silently in the active server pool but surface a count + reason list in the subscription detail page (e.g. *"3 servers skipped: vmess (legacy), shadowsocks (legacy), reality+grpc (invalid combination)"*). Never crash on a malformed entry.

### 5.4 Subscription update policy

- Auto-refresh interval: user-configurable, default 6h
- Always over HTTPS; reject `http://` subscription URLs
- Cache last good response; if refresh fails, keep serving cached pool and surface a non-blocking warning

---

## 6. Routing

### 6.1 Default rule set

| Match | Decision |
|-------|----------|
| `geoip:private` | direct |
| `geoip:cn` | direct |
| `geosite:cn` | direct |
| `geosite:apple-cn`, `geosite:google-cn`, `geosite:microsoft-cn` | direct |
| `geosite:category-ads-all` | block |
| everything else | proxy |

DNS:
- Domestic resolver: `223.5.5.5` (AliDNS) for `geosite:cn`
- Proxy resolver: `https://1.1.1.1/dns-query` (DoH) for everything proxied
- No system DNS leak: enforce `dns.servers` config

### 6.2 User overrides

Custom rules editor in UI compiles to standard Xray `routing.rules`. Keep the editor minimal — domain / IP / port / network, mapped to `direct` / `proxy` / `block`. No regex unless explicitly opted in (regex rules are slow and a footgun).

---

## 7. System integration

| Platform | Mode | Mechanism |
|----------|------|-----------|
| macOS | System proxy | `networksetup -setsocksfirewallproxy` |
| macOS | TUN | `utun` + `tun2socks` (statically linked) |
| Windows | System proxy | WinINET registry keys |
| Windows | TUN | `wintun.dll` + `tun2socks` |
| Linux | System proxy | `gsettings` (GNOME) / `kwriteconfig5` (KDE) / env vars |
| Linux | TUN | `/dev/net/tun` + `tun2socks` |

TUN is preferred (full system capture, including UDP and non-proxy-aware apps). System proxy is the fallback for users without admin rights.

---

## 8. Project layout

```
nexray/
├── DEVELOPMENT.md              # this file
├── README.md
├── docs/
│   ├── PROFILES.md             # deeper dive on each profile
│   ├── ARCHITECTURE.md         # diagrams + sequence flows
│   └── SECURITY.md             # threat model + handling rules
├── src/                        # React UI
│   ├── pages/
│   ├── components/
│   ├── stores/
│   └── lib/
│       ├── subscription.ts     # parser
│       ├── profile.ts          # Zod schemas (source of truth)
│       └── share-link.ts       # vless:// codec
├── src-tauri/                  # Rust shell
│   ├── src/
│   │   ├── main.rs
│   │   ├── core.rs             # xray sidecar lifecycle
│   │   ├── config.rs           # profile -> xray JSON
│   │   ├── subscription.rs
│   │   ├── proxy.rs            # system proxy
│   │   ├── tun.rs              # TUN mode
│   │   └── stats.rs            # xray Stats API poll
│   ├── binaries/               # bundled xray-core per arch
│   └── Cargo.toml
├── scripts/
│   └── fetch-core.mjs          # download xray-core release artifacts
├── package.json
├── pnpm-workspace.yaml
└── vite.config.ts
```

---

## 9. Build & dev workflow

```bash
# 1. install JS deps
pnpm install

# 2. fetch xray-core binaries for all platforms
pnpm run fetch-core

# 3. dev (hot reload UI, auto-restart shell on Rust changes)
pnpm tauri dev

# 4. release build (per platform)
pnpm tauri build
```

CI (GitHub Actions):
- Lint: `pnpm lint`, `cargo clippy --all-targets -- -D warnings`
- Type-check: `pnpm typecheck`
- Test: `pnpm test`, `cargo test`
- Release: matrix build on macOS-14, ubuntu-22.04, windows-latest; signs and uploads to Releases

---

## 10. Phased roadmap

| Phase | Deliverable | Acceptance |
|-------|-------------|------------|
| **0** | Repo skeleton, this guide, Zod schemas | Schemas reject every legacy share-link in the test corpus |
| **1** | Subscription parsing + profile validation (CLI) | Given a base64 sub URL, prints classified server list |
| **2** | Tauri shell with xray sidecar lifecycle | Connect / disconnect with hardcoded profile works on all 3 OS |
| **3** | Minimal UI: one profile, manual config | Manual `cdn-ws` and `reality` configs both connect |
| **4** | Subscription manager UI | Add / refresh / delete subs; pool view |
| **5** | Routing UI + presets | Default rule set works; user overrides persist |
| **6** | TUN mode | Full-system capture on at least macOS + Windows |
| **7** | Polish, code-sign, first release | Notarized macOS DMG; signed Windows MSI; AppImage |

---

## 11. Coding conventions

- **TypeScript**: `strict: true`, no `any`, no `as` unless cast through `unknown`. Errors are `Result`-like discriminated unions, not thrown.
- **Rust**: clippy clean. No `unwrap()` / `expect()` outside `main` and tests. Errors propagate through `thiserror` enums; never `Box<dyn Error>` at API boundaries.
- **IPC contract**: every Tauri command has a typed input + output, validated with Zod on the JS side and `serde` on the Rust side. The Zod schema is the single source of truth — Rust types are generated from it via `ts-rs` or matched manually with a CI check.
- **Strings**: English-first; UI strings go through `react-intl` with explicit IDs from day 1. No string concatenation for translatable text.
- **Logging**: `tracing` (Rust) + `consola` (JS). Never log UUIDs, public keys, short IDs, or full subscription URLs. Redact at the formatter, not the call site.

---

## 12. Security & privacy rules

These are non-negotiable; treat any PR that violates them as a bug.

1. Subscription fetch over HTTPS only. Reject `http://` URLs at parse time.
2. Never persist subscription credentials in plain text. macOS: Keychain. Windows: DPAPI. Linux: libsecret.
3. Validate `fingerprint` against the whitelist. An unknown value is a hard failure, not a fallback to default.
4. Refuse to materialize an Xray config if any mandatory field is missing — fail loudly with a structured error, never silently fill defaults that change semantics.
5. No telemetry. No crash reporting that ships data off-device by default. If added later, opt-in only and document exactly what is sent.
6. Stats are local-only. The Xray Stats API is bound to `127.0.0.1` with a random port, never exposed.
7. The bundled xray-core binary is pinned by SHA-256 in `scripts/fetch-core.mjs`. CI verifies the hash. Never auto-upgrade across releases.

---

## 13. Open design questions (decide before Phase 2)

- TUN library: ship our own `tun2socks` build, or depend on `sing-tun` from sing-box? (Lean: own build, fewer surprises.)
- Single-server vs. server-pool with latency-based selection in Phase 4? (Lean: pool from day 1, latency-based default.)
- Do we ship a system tray icon, or rely on the OS menu bar / taskbar only? (Lean: tray with minimal menu.)
- Auto-update mechanism (Tauri updater vs. manual)? (Lean: Tauri updater behind an opt-in toggle.)

Resolve these in `docs/ARCHITECTURE.md` before starting the corresponding phase.
