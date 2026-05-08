# Third-Party Licenses

Nexray bundles or depends on the following third-party components.
These components are governed by their own licenses, **not** by Nexray's
proprietary license. Their inclusion in the Nexray installer constitutes
"mere aggregation" under their respective copyleft terms where applicable
— Nexray does not modify, fork, or relicense any of them.

The full text of each upstream license accompanies the software where
its respective license requires it (e.g., the MPL-2.0 LICENSE shipped
inside the `xray-core` archive is preserved alongside the binary in
`binaries/<target-triple>/LICENSE` of each installer).

---

## xray-core

- **Upstream**: <https://github.com/XTLS/Xray-core>
- **License**: Mozilla Public License Version 2.0 (MPL-2.0)
- **License text**: <https://www.mozilla.org/en-US/MPL/2.0/>
- **Bundled as**: precompiled binary at `binaries/<triple>/xray[.exe]`,
  invoked as a separate child process. Source code form is available
  at the upstream repository above.

The MPL-2.0 file-level copyleft applies only to xray-core's own source
files. Nexray's own source is in separate files and is not, and need
not be, MPL-licensed (per MPL-2.0 §3.3 — Larger Works).

## tun2socks

- **Upstream**: <https://github.com/xjasonlyu/tun2socks>
- **License**: MIT License
- **License text**: <https://github.com/xjasonlyu/tun2socks/blob/main/LICENSE>
- **Bundled as**: precompiled binary at `binaries/<triple>/tun2socks[.exe]`,
  invoked as a separate child process when TUN mode is enabled.

## geoip.dat, geosite.dat (Loyalsoldier/v2ray-rules-dat)

- **Upstream**: <https://github.com/Loyalsoldier/v2ray-rules-dat>
- **License**: GNU General Public License v3.0 (GPL-3.0)
- **License text**: <https://www.gnu.org/licenses/gpl-3.0.txt>
- **Bundled as**: unmodified data blobs at `binaries/<triple>/geoip.dat`
  and `binaries/<triple>/geosite.dat`. Loaded at runtime by xray-core
  (also a separate executable) for `geoip:cn` / `geosite:cn` rule
  matching. The data is end-user-replaceable.

Aggregating these data files in the same installer as Nexray's
proprietary code is permitted under GPL-3.0 §5 ("Conveying Modified
Source Versions") so long as the GPL-licensed work is not modified
and recipients are made aware of its license. Source for the data
sets, including their build scripts, is available at the upstream
repository above.

## NPM and Cargo dependencies

The frontend and backend pull in a tree of upstream packages via
`pnpm` and `cargo`. Each remains under its own license (predominantly
MIT, Apache-2.0, BSD-3-Clause, ISC). A complete machine-readable
inventory is available locally with:

```bash
# Cargo:
cargo install cargo-license   # one time
cargo license

# pnpm:
pnpm licenses list
```

---

## Reporting a license concern

If you believe an attribution above is incomplete or incorrect, please
contact the copyright holder named in the top-level `LICENSE` file.
