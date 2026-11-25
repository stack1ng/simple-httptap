// Adapted from mitmproxy_rs (MIT, see LICENSE-mitmproxy): UDP goes through a SOCKS5 relay instead of protobuf IPC.

import NetworkExtension

/// Inbound and outbound copying for TCP flows, based on https://developer.apple.com/documentation/networkextension/app_proxy_provider/handling_flow_copying
extension NEAppProxyTCPFlow {
    func outboundCopier(_ conn: NWConnection) {
        readData { data, error in
            if error == nil, let readData = data, !readData.isEmpty {
                conn.send(
                    content: readData,
                    completion: .contentProcessed({ error in
                        if error == nil {
                            self.outboundCopier(conn)
                        } else {
                            self.closeConnection(conn, error)
                        }
                    }))
            } else {
                conn.send(content: nil, isComplete: true, completion: .contentProcessed({ error in
                    if error != nil {
                        self.closeConnection(conn, error)
                    }
                }))
            }
        }
    }

    func inboundCopier(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { (data, _, isComplete, error) in
            if let data, !data.isEmpty {
                self.write(data) { error in
                    if error == nil {
                        if isComplete {
                            self.closeConnection(conn, nil)
                        } else {
                            self.inboundCopier(conn)
                        }
                    } else {
                        self.closeConnection(conn, error)
                    }
                }
            } else {
                self.closeConnection(conn, error)
            }
        }
    }
}

/// Inbound and outbound copying for UDP flows, through the relay of a SOCKS5 UDP association.
extension NEAppProxyUDPFlow {
    func readDatagrams() async throws -> ([Data], [NetworkExtension.NWEndpoint]) {
        return try await withCheckedThrowingContinuation { continuation in
            readDatagrams { datagrams, endpoints, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: (datagrams ?? [], endpoints ?? []))
            }
        }
    }

    func outboundCopier(_ relay: NWConnection, control: NWConnection) {
        Task {
            do {
                while true {
                    let (datagrams, endpoints) = try await readDatagrams()
                    if datagrams.isEmpty { break }
                    for (datagram, endpoint) in zip(datagrams, endpoints) {
                        guard let endpoint = endpoint as? NWHostEndpoint, let port = UInt16(endpoint.port) else { continue }
                        try await relay.sendAll(try Socks.wrap(datagram, host: endpoint.hostname, port: port))
                    }
                }
                self.closeAssociation(relay, control: control, nil)
            } catch {
                log.error("Error in outbound UDP copier: \(String(describing: error), privacy: .public)")
                self.closeAssociation(relay, control: control, error)
            }
        }
    }

    func inboundCopier(_ relay: NWConnection, control: NWConnection) {
        Task {
            do {
                while let datagram = try await relay.receiveDatagram() {
                    guard let (host, port, payload) = Socks.unwrap(datagram) else { continue }
                    let endpoint = NWHostEndpoint(hostname: host, port: String(port))
                    try await self.writeDatagrams([payload], sentBy: [endpoint])
                }
                self.closeAssociation(relay, control: control, nil)
            } catch {
                log.error("Error in inbound UDP copier: \(String(describing: error), privacy: .public)")
                self.closeAssociation(relay, control: control, error)
            }
        }
    }

    func closeAssociation(_ relay: NWConnection, control: NWConnection, _ error: Error?) {
        relay.cancel()
        control.cancel()
        self.closeReadWithError(error)
        self.closeWriteWithError(error)
    }
}

extension NEAppProxyFlow {
    func closeConnection(_ conn: NWConnection, _ error: Error?) {
        conn.cancel()
        self.closeReadWithError(error)
        self.closeWriteWithError(error)
    }
}
