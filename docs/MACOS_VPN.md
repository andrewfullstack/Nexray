# macOS Network Extension — design + integration plan

This document describes how Nexray will eventually appear in
**System Settings → VPN** the same way Shadowrocket does. The work is
**deferred**: it requires Apple Developer Program membership, an explicit
NetworkExtension entitlement approval from Apple, and a separate Swift
target that lives outside the Rust + TS workspace.

The rest of this file is the integration plan — read top-to-bottom when the
project is ready to take this on.

## Why Network Extension?

A "VPN config" entry in Settings → VPN is implemented via Apple's
[`NEPacketTunnelProvider`][1] — a subclass of `NEProvider` that runs as a
sandboxed extension owned by macOS but bundled inside the host app. macOS
hands raw IP packets to the extension; the extension proxies / routes /
encrypts them. The user toggles a single switch — no sudo prompts, no
manual route fiddling, the OS handles routing primitives.

[1]: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider

Compared with the alternatives Nexray already supports:

| Approach | Friction | UX | Cross-platform |
|----------|----------|----|----------------|
| **System proxy** (`networksetup`) | Sudo prompt on toggle | Captures proxy-aware apps only | macOS / Windows / Linux equivalents |
| **TUN mode** (`tun2socks` + route table) | Sudo prompt on toggle, manual route reset on crash | Captures every packet | All three OSes |
| **Network Extension** (this doc) | Single confirmation at install, no recurring prompts | Captures every packet | macOS only |

NE is gold-standard for macOS. The other two stay as fallbacks for
unsigned / dev / Linux / Windows builds.

## Apple Developer prerequisites

**1.** Enroll in the [Apple Developer Program](https://developer.apple.com/programs/) — $99/year.

**2.** Request the `com.apple.developer.networking.networkextension` entitlement. As of macOS 10.15, this requires explicit Apple approval — fill in [the request form](https://developer.apple.com/contact/request/networkextension-entitlement). Apple typically approves VPN tunnel use cases within ~1 week.

**3.** Generate a provisioning profile that pairs the host app's bundle ID with the entitlement, and a second one for the NE extension's bundle ID (suffixed `.NetworkExtension`).

**4.** Both bundles must be signed with the same Developer ID + Team ID.

Without all four steps, a Network Extension binary won't load — macOS refuses to register it.

## Target layout

The Network Extension is its own bundle inside the host app:

```
Nexray.app/
├── Contents/
│   ├── MacOS/
│   │   └── Nexray                    # the Tauri host
│   ├── Resources/
│   │   └── ...
│   └── PlugIns/
│       └── NexrayTunnel.appex/       # the Network Extension
│           ├── Contents/
│           │   ├── MacOS/
│           │   │   └── NexrayTunnel  # the Swift extension binary
│           │   └── Info.plist
│           └── ...
```

The extension can't be built by `cargo` or `tauri build`. It needs an Xcode
project (or equivalent `xcodebuild` invocation) that:

1. Compiles `macos/NetworkExtension/PacketTunnelProvider.swift` against the
   `NetworkExtension.framework`.
2. Signs with `Developer ID Application` for distribution.
3. Embeds the resulting `NexrayTunnel.appex` into the host's `PlugIns/`
   directory at packaging time.

## Integration steps (when ready)

**Step 1.** Land the entitlement files. Stubbed in `macos/NetworkExtension/`
already.

**Step 2.** Build the extension. Add an Xcode project under
`macos/NetworkExtension/NexrayTunnel.xcodeproj` that compiles
`PacketTunnelProvider.swift` into a `NexrayTunnel.appex`. The Swift file
already has the skeleton — fill in the `startTunnel` / `handleAppMessage`
methods.

**Step 3.** Bridge to xray-core. The extension talks to `nexray-core`'s
parser (sharing the `Profile` schema) but needs xray-core to handle
the actual VLESS protocol. Two options:
- Spawn xray-core as a subprocess of the extension (matching what the host
  already does). The extension reads packets from `packetFlow`, forwards
  them to a SOCKS port on `127.0.0.1` that xray-core is listening on.
- Embed a Rust SOCKS5 → VLESS proxy directly in the extension via a
  static library built from `nexray-core`. Heavier but zero subprocess.

**Step 4.** Wire UI. The Tauri host calls `NETunnelProviderManager` Swift
APIs to install / start / stop the extension via a thin Obj-C bridge
exposed to Rust. Surface as a "VPN mode" radio in the existing capture-mode
UI (alongside System proxy and TUN).

**Step 5.** Bundle. Update `tauri.conf.json` to embed the `.appex` plug-in.
Tauri doesn't natively understand Network Extension targets; the
`tauri build` step needs a `beforeBundleCommand` that runs `xcodebuild` on
the NE project and copies the resulting `.appex` into the host bundle's
`PlugIns/` directory before final code-signing.

## Status

- [x] Architecture written down (this file)
- [x] `macos/NetworkExtension/` scaffold (entitlements + Info.plist + Swift skeleton)
- [ ] Apple Developer Program enrolment
- [ ] NE entitlement approval
- [ ] Xcode project for the extension target
- [ ] Wire to xray-core / `nexray-core`
- [ ] `NETunnelProviderManager` host-side bridge
- [ ] Tauri bundle integration

## Why we ship the system-proxy fallback today

`networksetup` is built into macOS, doesn't need any developer-program
membership, and gives a "feels like a VPN" experience for every
proxy-aware app — Safari, Chrome, curl, Mail, most CLI tools. Toggle
prompts for sudo once per change; afterwards the OS routes proxy-aware
traffic through Nexray's local SOCKS listener until the toggle goes off.

It's the highest-value capture mode we can ship without infrastructure
investments. Network Extension is the polish on top of that, not a
replacement for it.
