# Nexray

[English](README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [Русский](README.ru.md)

Modern, minimal VLESS + Trojan + VMess proxy client for macOS, Linux, and Windows.
Tray-app simple, kernel-grade fast.

## Download

- **All platforms** → <https://github.com/andrewfullstack/Nexray-App/releases/latest>
- **Site with auto-OS-detect download button** → <https://andrewfullstack.github.io/Nexray-App/>

| Platform              | Architecture | Installer                               |
| --------------------- | ------------ | --------------------------------------- |
| macOS (Apple Silicon) | aarch64      | `Nexray_<version>_aarch64.dmg`          |
| Linux                 | x86_64       | `nexray_<version>_amd64.deb`            |
| Windows               | x86_64       | `Nexray_<version>_x64-setup.exe`        |

## First launch — bypass the unsigned-binary warnings

The current builds are unsigned. macOS will refuse to open the `.dmg`
on first launch and Windows SmartScreen warns before running the `.exe`.
Both are bypassed in seconds:

### macOS — clear the quarantine flag

After dragging `Nexray.app` into `/Applications`, run this once in
Terminal (you'll be prompted for your password):

```bash
sudo xattr -dr com.apple.quarantine /Applications/Nexray.app
```

Then double-click as normal. Subsequent updates installed to the same
path don't need the command repeated.

### Windows — Run anyway

Double-click the `.exe`. SmartScreen shows **"Windows protected your PC"**.
Click **More info** → **Run anyway**. The warning appears only on first
launch of each version.

## Highlights

- **Modern protocols only.** VLESS (CDN-WS or REALITY), Trojan (TCP+TLS),
  and VMess (TCP+TLS, AEAD-only). Refuses Shadowsocks, the WebSocket
  variants of vmess/trojan, and every other legacy or insecure-by-default
  combination — by design.
- **Subscription import** with per-group **Auto** mode that probes latency
  and pins the active server to the fastest member of the group.
- **Smart routing.** Built-in `geosite:cn` rules + your own `rules.conf`.
  Domestic sites stay direct, ads blocked, everything else proxied.
- **System-wide via TUN.** Kernel-level packet capture for apps that ignore
  SOCKS. Safe-restore on quit — no orphaned routes.
- **Five UI languages.** English, 简体中文, 繁體中文, Русский. Auto-detected from
  your system, switchable in Settings.
- **Privacy by default.** No telemetry, no auto-updater traffic, no phone
  home unless you explicitly enable Auto-update in Settings.

## How this repository works

This repo (`Nexray-App`) holds only the public release artifacts and the
download landing page — it has **no source code**.

- `gh-pages` branch → renders <https://andrewfullstack.github.io/Nexray-App/>
- Releases → installer binaries (`.dmg` / `.deb` / `.exe`)

Source is maintained in a separate private repository; tagged releases
trigger a CI pipeline that builds installers and force-publishes them
(plus this README and the Pages site) here.

## License

Proprietary — all rights reserved. Copying, modification, redistribution,
or derivative work is not permitted without prior written consent of the
copyright holder. The installer binaries above are licensed for personal
use; contact the owner for any other use case.

Bundled third-party components remain under their respective upstream
licenses. The full per-component breakdown — including the MPL-2.0
notice for `xray-core`, the MIT notice for `tun2socks`, and the GPL-3.0
notice for the geoip/geosite data files — ships inside every installer
as `THIRD_PARTY_LICENSES.md`.
