# Deploying VLESS + Vision + REALITY (raw TCP) — 2026-05-07

Reproducible record of the REALITY server we stood up on **2026-05-07** as
the upstream for `repro_reality_e2e` (`src-tauri/tests/repro_reality_e2e.rs`).
What follows is exactly what ran over SSH, in order, with the values that
were actually used.

> **Secrets in this file.** The IP, UUID, and `privateKey` below match the
> live server. Anyone who can read this file can connect as us. If this repo
> ever goes public, rotate the keypair (`xray x25519`), regenerate UUID and
> shortId, restart the service, and commit a redacted version. Treat this
> file like `~/.ssh/id_rsa`.

---

## 0. Inventory

| | |
|---|---|
| Cloud | Google Cloud Platform — project `opcify`, zone `us-central1-c` |
| Instance | `instance-20260507-195334` |
| Public IP | `35.188.65.62` |
| SSH alias | `vless` (user `techsiderau`, key `~/.ssh/id_rsa_techsiderau`) |
| Distro | Debian-family, 9.7 GB root, 3.8 GB RAM, no swap |
| Xray version | `v25.1.30` (manual binary drop, **not** the install-release.sh script) |
| Listener | `0.0.0.0:443` |
| SNI camouflage (`dest` + `serverNames`) | `www.microsoft.com:443` |
| Flow | `xtls-rprx-vision` |
| Transport | raw `tcp` |
| Security | `reality` |

Why these picks:

- **GCP firewall, not ufw.** GCP's network-layer firewall rule fronts the VM,
  so `ufw` is unused on the box. Ingress on TCP/443 is opened in the GCP
  console (or `gcloud compute firewall-rules create`), not on the host.
- **Manual install, not the XTLS script.** Pinning the binary by SHA-256
  gives us a hermetic, replayable deploy. The script is convenient but pulls
  whatever `latest` is at install time.
- **`www.microsoft.com` as the steal-from target.** Has TLS 1.3, HTTP/2,
  long-lived OCSP, and unremarkable global traffic. Same fixture used by
  the `step1_share_link_decodes_to_reality_profile` test fixture in
  `repro_reality_e2e.rs`.

---

## 1. Connect

The Mac has an SSH alias for this host:

```sh
ssh vless 'whoami && hostnamectl --static && uname -a'
```

Equivalent to:

```sh
ssh -i ~/.ssh/id_rsa_techsiderau techsiderau@35.188.65.62 ...
```

All remaining commands run over that connection. Where this doc shows
`ssh vless '<cmd>'`, you can also paste `<cmd>` into an interactive shell.

---

## 2. Install Xray (manual, SHA-256 pinned)

```sh
ssh vless 'sudo bash -s' <<'REMOTE'
set -euo pipefail

XRAY_VERSION=v25.1.30
EXPECTED_SHA=cb13b75e36d1bafefebee5b3df42cb6f56009feb50d4c7eba5a35e7c46ea1bc8

cd /tmp
curl -fsSL -o xray.zip \
  "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip"

# Pin: refuse to install if the tarball was tampered with on the mirror.
echo "${EXPECTED_SHA}  xray.zip" | sha256sum -c -

rm -rf /tmp/xray-extract
unzip -qo xray.zip -d /tmp/xray-extract

install -m 0755 /tmp/xray-extract/xray            /usr/local/bin/xray
install -m 0644 /tmp/xray-extract/geoip.dat       /usr/local/bin/geoip.dat
install -m 0644 /tmp/xray-extract/geosite.dat     /usr/local/bin/geosite.dat

/usr/local/bin/xray version    # → Xray 25.1.30 …
REMOTE
```

---

## 3. Generate the REALITY identity

Three pieces of cryptographic material:

```sh
ssh vless 'sudo bash -s' <<'REMOTE'
set -euo pipefail

# 1. x25519 keypair — server keeps the private half, clients embed the public.
/usr/local/bin/xray x25519
# Output captured (do not regenerate unless rotating):
#   PrivateKey: 0Jnd5jedF2ANveqLOHtla9XfG6YE56Xj_oQcc4SH4lU
#   Password:   Apzam_TwrNUbuyFNstaT7HupqiDb45YoFHW8Oc8ACjo
#   Hash32:     WUUpnd5lNLlI0DseGNq3mtuv-ISyJiG82-nIClW67ws

# 2. UUID for the single client we provision.
/usr/local/bin/xray uuid
#   → 1ff005a9-ee81-4933-9843-1044210b6ade

# 3. Short ID — 8 random bytes, hex-encoded.
openssl rand -hex 8
#   → b2eefe61f3e114cb
REMOTE
```

Final values, used everywhere below:

```
PrivateKey  0Jnd5jedF2ANveqLOHtla9XfG6YE56Xj_oQcc4SH4lU   # server only
PublicKey   Apzam_TwrNUbuyFNstaT7HupqiDb45YoFHW8Oc8ACjo   # clients use as pbk=
ShortID     b2eefe61f3e114cb                              # clients use as sid=
UUID        1ff005a9-ee81-4933-9843-1044210b6ade          # the client identity
```

---

## 4. Write the server config

```sh
ssh vless 'sudo bash -s' <<'REMOTE'
set -euo pipefail

mkdir -p /usr/local/etc/xray /var/log/xray

cat >/usr/local/etc/xray/config.json <<'JSON'
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error":  "/var/log/xray/error.log"
  },
  "inbounds": [{
    "tag": "vless-in",
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{
        "id": "1ff005a9-ee81-4933-9843-1044210b6ade",
        "flow": "xtls-rprx-vision",
        "email": "nexray-test@local"
      }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "www.microsoft.com:443",
        "xver": 0,
        "serverNames": ["www.microsoft.com"],
        "privateKey": "0Jnd5jedF2ANveqLOHtla9XfG6YE56Xj_oQcc4SH4lU",
        "shortIds": ["b2eefe61f3e114cb"]
      }
    },
    "sniffing": {
      "enabled": true,
      "destOverride": ["http", "tls", "quic"],
      "routeOnly": true
    }
  }],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom",   "settings": {} },
    { "tag": "block",  "protocol": "blackhole", "settings": {} }
  ],
  "routing": {
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }
    ]
  }
}
JSON

# Config holds the private key — locked down so only root reads it.
chmod 600 /usr/local/etc/xray/config.json

# Quick syntax check before we wire systemd to it.
/usr/local/bin/xray test -config /usr/local/etc/xray/config.json
REMOTE
```

A few things worth knowing about this config:

- **`dest` and `serverNames` must align with a real, healthy TLS 1.3 host.**
  `www.microsoft.com` is in both. If Microsoft drops TLS 1.3 (unlikely) or
  starts presenting a different certificate chain, the camouflage breaks.
- **`xver: 0`** means we are not behind a PROXY-protocol load balancer. We
  speak directly to clients on `:443`.
- **`sniffing.routeOnly: true`** lets the routing rules see the real
  destination after VLESS decapsulation, without forcing the outbound to
  use the sniffed name (which would defeat REALITY-fronted traffic).
- **`geoip:private` → block`** stops the VPS from being used as a hop into
  RFC1918 networks if anyone ever points a buggy client at it.

---

## 5. systemd unit

```sh
ssh vless 'sudo bash -s' <<'REMOTE'
set -euo pipefail

cat >/etc/systemd/system/xray.service <<'UNIT'
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

# Hardening
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=/usr/local/etc/xray /var/log/xray

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable xray
systemctl restart xray
systemctl --no-pager status xray
REMOTE
```

`ProtectSystem=strict` initially blocks log writes — `ReadWritePaths=`
covers `/var/log/xray` and `/usr/local/etc/xray`, which is enough for
this config. If you add logs elsewhere, extend `ReadWritePaths=`.

---

## 6. Open the GCP firewall

`ufw` is not installed and not enabled on this host. Ingress is controlled
at the GCP network layer.

```sh
# Run from the Mac, where gcloud is authenticated.
gcloud compute firewall-rules create allow-reality-tcp443 \
  --project=opcify \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:443 \
  --source-ranges=0.0.0.0/0 \
  --target-tags=reality
```

Then attach the `reality` network tag to the VM (one-time):

```sh
gcloud compute instances add-tags instance-20260507-195334 \
  --project=opcify --zone=us-central1-c --tags=reality
```

---

## 7. Verify on the server

```sh
ssh vless 'sudo bash -s' <<'REMOTE'
# Process is up
systemctl is-active xray

# Listener is bound
ss -tlnp | grep ':443'
#   LISTEN 0 4096 *:443 *:* users:(("xray",pid=...,fd=10))

# No errors in the last minute of logs
journalctl -u xray --since '1 min ago' --no-pager
REMOTE
```

---

## 8. Verify from the Mac (end-to-end)

The share link captured from the deploy:

```
vless://1ff005a9-ee81-4933-9843-1044210b6ade@35.188.65.62:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=Apzam_TwrNUbuyFNstaT7HupqiDb45YoFHW8Oc8ACjo&sid=b2eefe61f3e114cb&type=tcp#nexray-reality-test
```

Run the live E2E test against it (`#[ignore]`'d so normal `cargo test`
doesn't touch the network):

```sh
export NEXRAY_REALITY_SHARE_LINK='vless://1ff005a9-ee81-4933-9843-1044210b6ade@35.188.65.62:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=Apzam_TwrNUbuyFNstaT7HupqiDb45YoFHW8Oc8ACjo&sid=b2eefe61f3e114cb&type=tcp#nexray-reality-test'
export NEXRAY_REALITY_SERVER_IP='35.188.65.62'

cargo test -p nexray --test repro_reality_e2e \
  step3_reality_tunnel_establishes_and_traffic_egresses_via_server \
  -- --ignored --nocapture
```

Expected output (ours, on 2026-05-07):

```
direct egress (control): 2401:d005:a105:1500:f11e:cf5f:76ec:be76
egress through REALITY proxy: 35.188.65.62
✓ proxied egress = server public IP 35.188.65.62
test step3_reality_tunnel_establishes_and_traffic_egresses_via_server ... ok
```

Step 4 also exercises the `default`, `direct`, and `global` routing
presets and checks each routes correctly:

```sh
cargo test -p nexray --test repro_reality_e2e \
  step4_all_three_presets_route_through_reality_upstream \
  -- --ignored --nocapture
```

Optional: capture a handshake for inspection.

```sh
ssh vless 'sudo tcpdump -i any -nn -w /tmp/reality.pcap "host <YOUR_CLIENT_IP> and tcp port 443"' &
# … run the test from the Mac …
kill %1
ssh vless 'sudo cat /tmp/reality.pcap' >/tmp/reality.pcap
```

---

## 9. Operational notes

- **No BBR / sysctl tuning.** Default Debian congestion control (CUBIC)
  is fine for the bandwidth we're testing at. Revisit if the server moves
  to bulk-throughput territory.
- **Logs.** `/var/log/xray/{access,error}.log`. `loglevel: warning` keeps
  steady-state quiet; bump to `info` only when debugging a specific client.
- **Updating Xray.** Re-run §2 with a new `XRAY_VERSION` and the new
  release's SHA-256, then `systemctl restart xray`. Don't trust `latest`.
- **Rotating REALITY keys.** Re-run §3, paste new `privateKey` / `shortIds`
  into §4's config, restart. Old shortIds/UUIDs become unusable
  immediately, so coordinate with whoever holds the share link.
- **Watching for leaks.** `xray` does not bind a control plane on this box.
  If you ever enable the gRPC API (`api` inbound), bind it to `127.0.0.1`
  and gate it behind SSH port-forwarding — never expose it on `0.0.0.0`.

---

## 10. Tear-down (if needed)

```sh
ssh vless 'sudo bash -s' <<'REMOTE'
systemctl disable --now xray
rm -f /etc/systemd/system/xray.service
systemctl daemon-reload

rm -rf /usr/local/etc/xray /var/log/xray
rm -f  /usr/local/bin/xray /usr/local/bin/geoip.dat /usr/local/bin/geosite.dat
REMOTE

gcloud compute firewall-rules delete allow-reality-tcp443 \
  --project=opcify --quiet
```
