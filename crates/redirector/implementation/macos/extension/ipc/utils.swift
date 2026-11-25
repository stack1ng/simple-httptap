// Adapted from mitmproxy_rs (MIT, see LICENSE-mitmproxy); the protobuf IPC is replaced by SOCKS5 to httptap's proxy.

import Foundation
import Network
import NetworkExtension

enum IpcError: Error {
    case incompleteRead
    case connectionCancelled
}

enum SocksError: Error, CustomStringConvertible {
    case noAcceptableMethod
    case refused(UInt8)
    case malformed
    case badAddress(String)

    var description: String {
        switch self {
        case .noAcceptableMethod: return "the SOCKS5 proxy accepted no method without authentication"
        case .refused(let status): return "the SOCKS5 proxy refused the request with status \(status)"
        case .malformed: return "the SOCKS5 proxy sent a malformed reply"
        case .badAddress(let host): return "the address \(host) cannot be sent over SOCKS5"
        }
    }
}

extension NWConnection {
    /// Starts the connection and waits until it is ready, or throws why it failed.
    func establish() async throws {
        let original = self.stateUpdateHandler
        defer {
            self.stateUpdateHandler = original
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            var resumed = false
            self.stateUpdateHandler = { state in
                guard !resumed else { return }
                switch state {
                case .ready:
                    resumed = true
                    continuation.resume()
                case .waiting(let error), .failed(let error):
                    resumed = true
                    continuation.resume(throwing: error)
                case .cancelled:
                    resumed = true
                    continuation.resume(throwing: IpcError.connectionCancelled)
                default:
                    break
                }
            }
            self.start(queue: DispatchQueue.global())
        }
    }

    /// Sends the bytes, or one datagram on a UDP connection, and waits until they were handed to the system.
    func sendAll(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            self.send(content: data, completion: .contentProcessed({ error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }))
        }
    }

    /// Receives exactly the count of bytes, or throws if the connection ends first.
    func receiveExactly(_ count: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            self.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let data, data.count == count {
                    continuation.resume(returning: data)
                } else {
                    continuation.resume(throwing: IpcError.incompleteRead)
                }
            }
        }
    }

    /// Receives one datagram, or none once the connection ended.
    func receiveDatagram() async throws -> Data? {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            self.receiveMessage { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let data {
                    continuation.resume(returning: data)
                } else if isComplete {
                    continuation.resume(returning: nil)
                } else {
                    continuation.resume(returning: Data())
                }
            }
        }
    }
}

/// A client of SOCKS5 (RFC 1928) that asks httptap's proxy for a TCP connection or a UDP relay.
enum Socks {
    static let version: UInt8 = 5
    static let noAuthentication: UInt8 = 0
    static let connect: UInt8 = 1
    static let udpAssociate: UInt8 = 3
    static let ipv4: UInt8 = 1
    static let domainName: UInt8 = 3
    static let ipv6: UInt8 = 4

    /// Returns a host and port in SOCKS5's form: an IP address if the host is one, or else a domain name.
    static func encode(host: String, port: UInt16) throws -> Data {
        var data = Data()
        let bare = host.split(separator: "%").first.map(String.init) ?? host
        if let address = IPv4Address(bare) {
            data.append(ipv4)
            data.append(address.rawValue)
        } else if let address = IPv6Address(bare) {
            data.append(ipv6)
            data.append(address.rawValue)
        } else {
            let name = Data(host.utf8)
            guard name.count <= Int(UInt8.max) else { throw SocksError.badAddress(host) }
            data.append(domainName)
            data.append(UInt8(name.count))
            data.append(name)
        }
        data.append(UInt8(port >> 8))
        data.append(UInt8(port & 0xff))
        return data
    }

    /// Returns the host and port at the start of the bytes, and how many bytes they took.
    static func decode(_ data: Data) -> (host: String, port: UInt16, size: Int)? {
        let bytes = [UInt8](data)
        guard let kind = bytes.first else { return nil }
        var host: String
        var offset: Int
        switch kind {
        case ipv4:
            guard bytes.count >= 1 + 4 + 2 else { return nil }
            host = IPv4Address(Data(bytes[1..<5]))!.debugDescription
            offset = 5
        case ipv6:
            guard bytes.count >= 1 + 16 + 2 else { return nil }
            host = IPv6Address(Data(bytes[1..<17]))!.debugDescription
            offset = 17
        case domainName:
            guard bytes.count >= 2 else { return nil }
            let length = Int(bytes[1])
            guard bytes.count >= 2 + length + 2 else { return nil }
            host = String(decoding: bytes[2..<(2 + length)], as: UTF8.self)
            offset = 2 + length
        default:
            return nil
        }
        let port = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        return (host, port, offset + 2)
    }

    /// Connects to the proxy, greets it and sends a request; returns the connection and the address in the reply.
    static func request(proxy: Network.NWEndpoint, command: UInt8, host: String, port: UInt16) async throws -> (NWConnection, String, UInt16) {
        let connection = NWConnection(to: proxy, using: .tcp)
        do {
            try await connection.establish()
            try await connection.sendAll(Data([version, 1, noAuthentication]))
            let chosen = try await connection.receiveExactly(2)
            guard chosen == Data([version, noAuthentication]) else { throw SocksError.noAcceptableMethod }
            var request = Data([version, command, 0])
            request.append(try encode(host: host, port: port))
            try await connection.sendAll(request)
            let head = try await connection.receiveExactly(4)
            guard head[head.startIndex] == version else { throw SocksError.malformed }
            let status = head[head.startIndex + 1]
            let kind = head[head.startIndex + 3]
            var rest: Data
            switch kind {
            case ipv4: rest = try await connection.receiveExactly(4 + 2)
            case ipv6: rest = try await connection.receiveExactly(16 + 2)
            case domainName:
                let length = try await connection.receiveExactly(1)
                rest = length + (try await connection.receiveExactly(Int(length[length.startIndex]) + 2))
            default: throw SocksError.malformed
            }
            guard status == 0 else { throw SocksError.refused(status) }
            guard let (boundHost, boundPort, _) = decode(Data([kind]) + rest) else { throw SocksError.malformed }
            return (connection, boundHost, boundPort)
        } catch {
            connection.cancel()
            throw error
        }
    }

    /// Asks the proxy for a TCP connection to the destination and returns it, ready to carry the flow's bytes.
    static func open(proxy: Network.NWEndpoint, host: String, port: UInt16) async throws -> NWConnection {
        let (connection, _, _) = try await request(proxy: proxy, command: connect, host: host, port: port)
        return connection
    }

    /// Asks the proxy for a UDP relay; returns the control connection that keeps it, and a UDP connection to the relay.
    static func associate(proxy: Network.NWEndpoint) async throws -> (control: NWConnection, relay: NWConnection) {
        let (control, host, port) = try await request(proxy: proxy, command: udpAssociate, host: "0.0.0.0", port: 0)
        var relayHost = host
        if relayHost == "0.0.0.0" || relayHost == "::", case .hostPort(let proxyHost, _) = proxy {
            relayHost = "\(proxyHost)"
        }
        let relay = NWConnection(host: Network.NWEndpoint.Host(relayHost), port: Network.NWEndpoint.Port(rawValue: port)!, using: .udp)
        do {
            try await relay.establish()
        } catch {
            control.cancel()
            throw error
        }
        return (control, relay)
    }

    /// Returns a datagram for the relay: the SOCKS5 UDP header naming the destination, then the payload.
    static func wrap(_ payload: Data, host: String, port: UInt16) throws -> Data {
        var datagram = Data([0, 0, 0])
        datagram.append(try encode(host: host, port: port))
        datagram.append(payload)
        return datagram
    }

    /// Returns the source and payload of a datagram from the relay, or none if it is malformed or a fragment.
    static func unwrap(_ datagram: Data) -> (host: String, port: UInt16, payload: Data)? {
        guard datagram.count > 3, datagram.prefix(3) == Data([0, 0, 0]) else { return nil }
        let rest = datagram.dropFirst(3)
        guard let (host, port, size) = decode(Data(rest)) else { return nil }
        return (host, port, Data(rest.dropFirst(size)))
    }
}
