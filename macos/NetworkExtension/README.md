# `NetworkExtension/` — scaffold for the macOS VPN extension

This directory holds the future `NEPacketTunnelProvider` extension that
will let Nexray show up in **System Settings → VPN** like Shadowrocket
does. It is **not yet wired into any build**.

See [`../../docs/MACOS_VPN.md`](../../docs/MACOS_VPN.md) for the full
architecture + Apple Developer Program prerequisites.

## What's here today

- `PacketTunnelProvider.swift` — skeleton subclass of
  `NEPacketTunnelProvider`. The `startTunnel` / `stopTunnel` methods are
  stubbed; the actual packet → SOCKS translation needs to be filled in.
- `Info.plist` — the `.appex` bundle's metadata. Sets the
  `NSExtensionPrincipalClass` so macOS knows which Swift class to
  instantiate.
- `NetworkExtension.entitlements` — the entitlements the extension itself
  needs (sandbox, NEPacketTunnelProvider, network-client / network-server).
- `Host.entitlements` — what the host Tauri app needs to *install* and
  *start* extensions (NEPacketTunnelProvider, network-client / server,
  application-groups for the bundle pair).

## What's missing

- An Xcode project / Swift package that compiles this into a `.appex`.
- The host-side Obj-C bridge that calls `NETunnelProviderManager` from
  Rust to install / start / stop the extension.
- A `tauri build` hook that invokes `xcodebuild` and embeds the resulting
  `.appex` into `Nexray.app/Contents/PlugIns/`.
- Apple Developer Program enrolment + NE entitlement approval.

## How to actually build this someday

```bash
# 1. Open the Xcode project (will need to be created):
open macos/NetworkExtension/NexrayTunnel.xcodeproj

# 2. Set the Team ID + provisioning profile to one that has the
#    `com.apple.developer.networking.networkextension` entitlement.

# 3. Build the .appex:
xcodebuild -project NexrayTunnel.xcodeproj \
  -scheme NexrayTunnel \
  -configuration Release \
  build

# 4. Tauri bundling will then copy build/Release/NexrayTunnel.appex into
#    Nexray.app/Contents/PlugIns/ during `tauri build`.
```
