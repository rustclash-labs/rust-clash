import Darwin
import Foundation
import NetworkExtension
import os.log

/// Native macOS System Extension (`NEPacketTunnelProvider`) bridging Apple's
/// `NEPacketTunnelFlow` L3 packets directly into `rust-clash` (`libproxy_ffi.a`).
///
/// Concurrency & Power Efficiency Architecture:
/// 1. Zero Use-After-Free (UAF): `stateLock` synchronizes `engineHandle` and `running` across
///    `startTunnel`, `stopTunnel`, `packetFlow.readPackets`, `egressQueue`, `wake()`, and
///    `handleAppMessage`, backed by Rust's `Arc`-counted opaque handle registry (`NE_ENGINES`).
///    `stopTunnel` unblocks the egress worker via `rc_ne_stop_engine` and waits on `egressGroup`
///    before invoking `completionHandler()`.
/// 2. `0 Hz` Idle CPU Wakeups: Replaces periodic `DispatchSourceTimer` polling with event-driven
///    blocking `rc_ne_wait_outbound_packet(handle, ..., -1)` + 64-packet non-blocking batch drain.
///
/// Note on distribution & signing:
/// Apple requires `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`)
/// signed by a paid Apple Developer ID / App Store provisioning profile for System Extensions.
/// Without those Apple credentials, `rust-clash` automatically uses its built-in `PF_SYSTEM`
/// `utun` kernel backend (`crates/proxy-core/src/platform/tun/macos.rs`).
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: "io.github.rustclashlabs.rustclash.ne", category: "PacketTunnel")
    private let stateLock = NSLock()
    private var engineHandle: OpaquePointer?
    private var stopRequested = false
    private let egressGroup = DispatchGroup()
    private let egressQueue = DispatchQueue(
        label: "io.github.rustclashlabs.rustclash.ne.egress",
        qos: .userInitiated
    )

    private func activeHandle() -> OpaquePointer? {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard !stopRequested else { return nil }
        return engineHandle
    }

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        stateLock.lock()
        stopRequested = false
        if let stale = engineHandle {
            engineHandle = nil
            stateLock.unlock()
            rc_ne_stop_engine(stale)
        } else {
            stateLock.unlock()
        }

        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let providerCfg = proto.providerConfiguration,
              let yamlConfig = providerCfg["yamlConfig"] as? String
        else {
            let err = NSError(
                domain: "io.github.rustclashlabs.rustclash.ne",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Missing yamlConfig in NETunnelProviderProtocol.providerConfiguration"]
            )
            completionHandler(err)
            return
        }

        let mtu = (providerCfg["mtu"] as? Int) ?? 1500
        let enableIpv6 = (providerCfg["enableIpv6"] as? Bool) ?? true
        let bypassServers = (providerCfg["bypassIps"] as? [String]) ?? []

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.1")
        settings.mtu = NSNumber(value: mtu)

        // IPv4 Fake-IP + full-tunnel capture with proxy server exclusions to prevent self-routing loops
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.254.0.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        var excludedV4: [NEIPv4Route] = []
        for ip in bypassServers where !ip.contains(":") {
            excludedV4.append(NEIPv4Route(destinationAddress: ip, subnetMask: "255.255.255.255"))
        }
        ipv4.excludedRoutes = excludedV4
        settings.ipv4Settings = ipv4

        if enableIpv6 {
            let ipv6 = NEIPv6Settings(addresses: ["fdfe:dcba:9876::1"], networkPrefixLengths: [126])
            ipv6.includedRoutes = [NEIPv6Route.default()]
            var excludedV6: [NEIPv6Route] = []
            for ip in bypassServers where ip.contains(":") {
                excludedV6.append(NEIPv6Route(destinationAddress: ip, networkPrefixLength: 128))
            }
            ipv6.excludedRoutes = excludedV6
            settings.ipv6Settings = ipv6
        }

        let dnsSettings = NEDNSSettings(servers: ["198.19.255.254"])
        dnsSettings.matchDomains = [""]
        settings.dnsSettings = dnsSettings

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else {
                completionHandler(
                    NSError(
                        domain: "io.github.rustclashlabs.rustclash.ne",
                        code: 3,
                        userInfo: [NSLocalizedDescriptionKey: "PacketTunnelProvider deallocated during setup"]
                    )
                )
                return
            }
            if let error = error {
                os_log(.error, log: self.log, "setTunnelNetworkSettings failed: %{public}@", error.localizedDescription)
                completionHandler(error)
                return
            }

            var errPtr: UnsafeMutablePointer<CChar>?
            let handle = yamlConfig.withCString { cYaml in
                rc_ne_start_engine(cYaml, UInt16(clamping: mtu), &errPtr)
            }

            guard let validHandle = handle else {
                let message: String
                if let errPtr = errPtr {
                    message = String(cString: errPtr)
                    rc_ne_free_string(errPtr)
                } else {
                    message = "rc_ne_start_engine failed"
                }
                let err = NSError(
                    domain: "io.github.rustclashlabs.rustclash.ne",
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: message]
                )
                completionHandler(err)
                return
            }

            // Check whether `stopTunnel` raced while `setTunnelNetworkSettings` / `rc_ne_start_engine` ran
            self.stateLock.lock()
            if self.stopRequested {
                self.stateLock.unlock()
                rc_ne_stop_engine(validHandle)
                let cancelledErr = NSError(
                    domain: "io.github.rustclashlabs.rustclash.ne",
                    code: 4,
                    userInfo: [NSLocalizedDescriptionKey: "Tunnel stopped while starting"]
                )
                completionHandler(cancelledErr)
                return
            }
            self.engineHandle = validHandle
            self.stateLock.unlock()

            self.startInboundPump(expectedHandle: validHandle)
            self.startOutboundPump(handle: validHandle)
            os_log(.info, log: self.log, "RustClash NEPacketTunnelProvider started (MTU=%d, idleWakeups=0Hz)", mtu)
            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        stateLock.lock()
        stopRequested = true
        let handleToStop = engineHandle
        engineHandle = nil
        stateLock.unlock()

        if let handle = handleToStop {
            // Atomically unregisters `handle` in Rust and wakes `rc_ne_wait_outbound_packet` immediately!
            rc_ne_stop_engine(handle)
        }

        // Wait for `egressQueue` worker to exit cleanly before signalling NE completion
        egressGroup.notify(queue: .main) { [log] in
            os_log(.info, log: log, "RustClash NEPacketTunnelProvider stopped cleanly (reason=%d)", reason.rawValue)
            completionHandler()
        }
    }

    override func wake() {
        guard let handle = activeHandle() else { return }
        _ = rc_ne_notify_network_change(handle)
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let handle = activeHandle() else {
            completionHandler?(nil)
            return
        }
        if let statusPtr = rc_ne_get_status_json(handle) {
            let json = String(cString: statusPtr)
            rc_ne_free_string(statusPtr)
            completionHandler?(json.data(using: .utf8))
        } else {
            completionHandler?(nil)
        }
    }

    private func startInboundPump(expectedHandle: OpaquePointer) {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self,
                  let current = self.activeHandle(),
                  current == expectedHandle
            else {
                return
            }
            for pkt in packets {
                pkt.withUnsafeBytes { rawBuf in
                    if let base = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                        _ = rc_ne_push_inbound_packet(current, base, rawBuf.count)
                    }
                }
            }
            if self.activeHandle() == expectedHandle {
                self.startInboundPump(expectedHandle: expectedHandle)
            }
        }
    }

    private func startOutboundPump(handle: OpaquePointer) {
        egressGroup.enter()
        egressQueue.async { [weak self] in
            defer { self?.egressGroup.leave() }
            var scratch = [UInt8](repeating: 0, count: 65536)

            while true {
                // Event-driven wait (`timeout_ms = -1`): blocks on Rust Condvar with 0 Hz idle wakeups!
                let firstLen = scratch.withUnsafeMutableBufferPointer { buf -> Int in
                    rc_ne_wait_outbound_packet(handle, buf.baseAddress, buf.count, -1)
                }
                if firstLen < 0 {
                    // Engine stopped (`rc_ne_stop_engine` called)
                    break
                }
                if firstLen == 0 {
                    continue
                }

                guard let self = self, self.activeHandle() == handle else {
                    break
                }

                var batch: [Data] = []
                batch.reserveCapacity(64)
                var protos: [NSNumber] = []
                protos.reserveCapacity(64)

                let appendScratchPacket: (Int) -> Void = { len in
                    let data = Data(bytes: scratch, count: len)
                    let ipVer = (scratch[0] >> 4)
                    let protoFamily: Int32 = (ipVer == 6) ? AF_INET6 : AF_INET
                    batch.append(data)
                    protos.append(NSNumber(value: protoFamily))
                }

                appendScratchPacket(firstLen)

                // Non-blockingly coalesce up to 63 additional queued packets into a single `writePackets` call
                for _ in 0..<63 {
                    let n = scratch.withUnsafeMutableBufferPointer { buf in
                        rc_ne_pop_outbound_packet(handle, buf.baseAddress, buf.count)
                    }
                    if n == 0 {
                        break
                    }
                    appendScratchPacket(n)
                }

                self.packetFlow.writePackets(batch, withProtocols: protos)
            }
        }
    }
}
