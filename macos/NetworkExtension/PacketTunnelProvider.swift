// PacketTunnelProvider — Network Extension skeleton.
//
// This file is NOT compiled by the Tauri build today. It's the starting
// point for the Phase 7.5+ macOS VPN target described in
// `docs/MACOS_VPN.md`. To make it real:
//
// 1. Create an Xcode project at `macos/NetworkExtension/NexrayTunnel.xcodeproj`
//    with a "Network Extension" target whose Info.plist points
//    `NSExtensionPrincipalClass` at this file's `PacketTunnelProvider` class.
// 2. Set the target's entitlements file to `NetworkExtension.entitlements`.
// 3. Sign with a Developer ID that has the
//    `com.apple.developer.networking.networkextension` entitlement.
// 4. Fill in the `// TODO`s below — most of the work is wiring the
//    `packetFlow` to xray-core's SOCKS listener.

import Foundation
import NetworkExtension
import os.log

/// Bundled inside the host app under `Nexray.app/Contents/PlugIns/NexrayTunnel.appex`.
/// macOS instantiates this class when the user toggles the VPN switch.
class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: "dev.nexray.app.tunnel", category: "PacketTunnelProvider")

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        os_log("startTunnel", log: log, type: .info)

        // TODO: read the Profile JSON from `protocolConfiguration.providerConfiguration`,
        //       materialize the xray config (use the same nexray-core schema),
        //       spawn xray-core (or link it as a static lib), bind the
        //       SOCKS listener, then translate `packetFlow` → SOCKS5 frames.

        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        networkSettings.ipv4Settings = NEIPv4Settings(addresses: ["10.10.10.2"], subnetMasks: ["255.255.255.0"])
        networkSettings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        networkSettings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1"])
        networkSettings.mtu = 1500

        setTunnelNetworkSettings(networkSettings) { error in
            if let error = error {
                os_log("setTunnelNetworkSettings failed: %{public}@", log: self.log, type: .error, String(describing: error))
                completionHandler(error)
                return
            }
            // TODO: start the read loop on packetFlow.readPackets(completionHandler:)
            //       and forward each packet to the local SOCKS listener.
            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        os_log("stopTunnel reason=%{public}d", log: log, type: .info, reason.rawValue)
        // TODO: shut down the xray-core child process / SOCKS listener and the
        //       packet read loop, then restore any state.
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // The host Tauri app talks to the running extension via this RPC.
        // Used for live status queries and config updates without a full
        // restart of the tunnel.
        completionHandler?(nil)
    }
}
