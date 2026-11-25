// Adapted from mitmproxy_rs (MIT, see LICENSE-mitmproxy): flows go to httptap's SOCKS5 proxy, chosen by process ancestry.

import Darwin
import Foundation
import Network
import NetworkExtension

enum TransparentProxyError: Error {
    case noRemoteEndpoint
    case unexpectedFlow
}

class TransparentProxyProvider: NETransparentProxyProvider {
    var server: ControlServer?

    override func startProxy(options: [String: Any]? = nil) async throws {
        log.debug("Starting proxy...")
        let server = try ControlServer(onIdle: { [weak self] in
            log.info("no program is captured any more, stopping the proxy")
            self?.cancelProxyWithError(nil)
        })
        server.start()
        self.server = server

        let proxySettings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        proxySettings.includedNetworkRules = [
            NENetworkRule(
                remoteNetwork: nil,
                remotePrefix: 0,
                localNetwork: nil,
                localPrefix: 0,
                protocol: .any,
                // https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings/3143656-includednetworkrules:
                // The matchDirection property must be NETrafficDirection.outbound.
                direction: .outbound
            )
        ]
        try await setTunnelNetworkSettings(proxySettings)
        log.debug("Proxy start complete.")
    }

    override func stopProxy(with reason: NEProviderStopReason) async {
        log.debug("stopProxy \(String(describing: reason), privacy: .public)")
        server?.stop()
        server = nil
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // Every new flow on the system comes here; only those of a captured program's process tree are taken.
        guard let server,
              let pid = Processes.pid(fromAuditToken: flow.metaData.sourceAppAuditToken),
              let capture = server.capture(forPid: pid)
        else { return false }

        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            guard let remote = tcpFlow.remoteEndpoint as? NWHostEndpoint, let port = UInt16(remote.port) else { return false }
            Task {
                do {
                    let connection = try await Socks.open(proxy: capture.proxy, host: remote.hostname, port: port)
                    try await tcpFlow.open(withLocalEndpoint: nil)
                    tcpFlow.outboundCopier(connection)
                    tcpFlow.inboundCopier(connection)
                } catch {
                    log.error("TCP flow of process \(pid, privacy: .public) to \(remote.hostname, privacy: .public):\(port, privacy: .public) failed: \(String(describing: error), privacy: .public)")
                    tcpFlow.closeReadWithError(error)
                    tcpFlow.closeWriteWithError(error)
                }
            }
            return true
        }
        if let udpFlow = flow as? NEAppProxyUDPFlow {
            Task {
                do {
                    let (control, relay) = try await Socks.associate(proxy: capture.proxy)
                    try await udpFlow.open(withLocalEndpoint: nil)
                    udpFlow.outboundCopier(relay, control: control)
                    udpFlow.inboundCopier(relay, control: control)
                } catch {
                    log.error("UDP flow of process \(pid, privacy: .public) failed: \(String(describing: error), privacy: .public)")
                    udpFlow.closeReadWithError(error)
                    udpFlow.closeWriteWithError(error)
                }
            }
            return true
        }
        return false
    }
}
