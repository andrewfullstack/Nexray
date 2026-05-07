# Profiles

Two profiles, no third one. The shapes below are canonical xray-core client
outbounds; the Rust shell materializes profiles into exactly this JSON.

See [`src/lib/profile.ts`](../src/lib/profile.ts) for the Zod source of truth
and [`DEVELOPMENT.md` §4](../DEVELOPMENT.md) for the validation rules.

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

VMess, Shadowsocks, ShadowsocksR, Trojan, Trojan-Go, HTTP/SOCKS as outbound,
REALITY combined with WebSocket / gRPC / XHTTP / HTTPUpgrade, plain VLESS+TLS
direct (without REALITY), mKCP, raw QUIC inbound. The classifier surfaces
these as skipped with a structured reason; nothing legacy lands in the pool.
