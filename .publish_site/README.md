# Nexray

Modern, minimal VLESS proxy client for macOS, Linux, and Windows.
Tray-app simple, kernel-grade fast.

## Download

- **All platforms** → <https://github.com/andrewfullstack/Nexray-App/releases/latest>
- **Site with auto-OS-detect download button** → <https://andrewfullstack.github.io/Nexray-App/>

| Platform              | Architecture | Installer                               |
| --------------------- | ------------ | --------------------------------------- |
| macOS (Apple Silicon) | aarch64      | `Nexray_<version>_aarch64.dmg`          |
| Linux                 | x86_64       | `nexray_<version>_amd64.deb`            |
| Windows               | x86_64       | `Nexray_<version>_x64-setup.exe`        |

> The macOS build is currently unsigned. On first launch right-click → **Open**
> to bypass Gatekeeper. Windows builds will show a SmartScreen warning until
> code-signing is configured.

## Highlights

- **VLESS only.** Refuses VMess, Shadowsocks, Trojan, and every other legacy
  or insecure-by-default combination — by design.
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

Bundled third-party components (xray-core, tun2socks, geoip/geosite
databases) remain under their respective upstream licenses.
