# Profiles

Two profiles, no third one. The shapes below are canonical xray-core client
outbounds; the Rust shell materializes profiles into exactly this JSON.

See [`src/lib/profile.ts`](../src/lib/profile.ts) for the Zod source of truth
and [`DEVELOPMENT.md` §4](../DEVELOPMENT.md) for the validation rules.

## Why only these two

`cdn-ws` and `reality` are the only deployment profiles where the
wire traffic — to a passive observer or an active prober — is
indistinguishable from a legitimate browser-to-CDN session, end to end:

- **TLS 1.3 handshake** with a real CDN's certificate (Cloudflare for
  `cdn-ws`, the borrowed SNI's CDN for `reality`).
- **Chrome-fingerprinted ClientHello** via uTLS (`fp=chrome` is the
  default), bit-indistinguishable from a real Chrome browser.
- **No proxy-shaped framing inside TLS** — Vision (REALITY) and standard
  WebSocket Upgrade (cdn-ws) are both well-known, well-distributed
  patterns, not custom layers a fingerprinting model can latch onto.
- **Active probes hit a real CDN's backend.** Probing the IP without
  client credentials lands on Cloudflare (cdn-ws) or the borrowed CDN's
  edge (reality), and gets a response indistinguishable from genuine CDN
  traffic — see `docs/SECURITY.md` for the threat model.

Every other protocol or transport combination listed in [_What we do
not support_](#what-we-do-not-support) has at least one of:
fingerprintable framing, observable handshake patterns, cert-chain
information leaks, or vulnerability to active probing. Operators have
been blocking those for years; we do not implement them by design.

## `cdn-ws`

VLESS + WebSocket + TLS, fronted by a CDN (typically Cloudflare).

```json
{
  "protocol": "vless",
  "settings": {
    "vnext": [{
      "address": "<cdn-edge-ip-or-host>",
      "port": 443,
      "users": [{ "id": "<uuid>", "encryption": "none" }]
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

Validation rules:
- `address` is often a clean Cloudflare edge IP, **not** the apex domain.
  `host` and `serverName` carry the real domain.
- `fingerprint` defaults to `chrome` and shapes the ClientHello even with WS.
- `allowInsecure: true` is rejected at parse time. The materializer always
  emits `false`.
- The early-data hint (`?ed=2560`) in `path` is preserved verbatim.

## `reality`

VLESS + Vision flow + REALITY over raw TCP.

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
      "serverName": "<dest-sni>",
      "fingerprint": "chrome",
      "publicKey": "<server-public-key>",
      "shortId": "<short-id>",
      "spiderX": ""
    }
  }
}
```

Validation rules:
- `flow` MUST equal `xtls-rprx-vision` (literal). Any other value is rejected.
- `network` MUST equal `tcp`. REALITY combined with `ws`, `grpc`, `xhttp`, or
  `httpupgrade` is rejected at parse time.
- `fingerprint` whitelist: `chrome`, `firefox`, `safari`, `ios`, `android`,
  `edge`, `random`. Unknown values are a hard failure, not a fallback.
- `serverName` is the **borrowed** SNI of the destination the server steals
  TLS from (e.g. `www.microsoft.com`), not the proxy server's own domain.
- `publicKey` is base64url, 43 chars (32-byte Curve25519, no padding).
- `shortId` is hex, 0–16 chars, **even length**.

## What we do not support

The classifier surfaces these as skipped with a structured reason;
nothing legacy lands in the pool. The reason each is rejected is
concrete, not aesthetic — every entry in this table has a known
weakness against the threat model in [`SECURITY.md`](./SECURITY.md).

| Rejected | Why |
|---|---|
| **VMess** | The custom AEAD header is fingerprint-able and the protocol's "no-header MD5" mode has known [active-probe attacks](https://github.com/v2fly/v2ray-core/issues/2523). Deprecated upstream; ships with a non-zero attack surface. |
| **Shadowsocks (SS), ShadowsocksR (SSR)** | Pre-TLS era. Stream cipher modes leak length distributions; even SS-2022's AEAD-2022 streams have observable connection-setup patterns and have been flagged by deep-packet-inspection systems. |
| **Trojan, Trojan-Go** | Relies on a fixed password-hash prefix immediately after the TLS handshake; an active prober can replay an arbitrary GET, observe whether the server rejects vs. proxies, and confirm a Trojan endpoint. REALITY's steal-routine doesn't have this oracle. |
| **VLESS + TLS direct (no REALITY, no CDN)** | The TLS cert is for a domain *you* control. The cert chain reveals the operator's domain, the SNI is uniquely yours, and post-handshake traffic patterns are fingerprintable as VLESS. REALITY fixes all three by impersonating a CDN. |
| **REALITY + WebSocket / gRPC / XHTTP / HTTPUpgrade** | REALITY's whole value is that post-handshake bytes look like a normal browser→CDN session. Layering an HTTP-style framing on top adds a structure (HTTP/2 frames, WebSocket Upgrade, chunked padding) that fingerprinting models can pick up. xray-core lets you build these combinations; the audit cost is too high for the camouflage value lost. |
| **mKCP / QUIC inbound / raw UDP transports** | UDP-based, with timing and packet-size patterns that are fingerprintable. No major CDN exposes a comparable camouflage target. |
| **HTTP / SOCKS as outbound transports** | No encryption, no camouflage. Useful only as the local *inbound* listener for the user's apps, never as the upstream link to the proxy server. |

If any of those land in your subscription, they're surfaced verbatim in
the "X servers skipped: …" line under each subscription, so you know
exactly why the count is what it is.
