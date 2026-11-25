// The control server httptap processes connect to, one connection per program they capture.

import Foundation
import Network
import NetworkExtension

/// The path of the control socket, where every httptap process registers the program it captures.
let controlSocketPath = "/var/run/com.stack1ng.simplehttptap.redirector.sock"
/// The first line the server writes to each client, which names the protocol and its version.
let protocolGreeting = "httptap-redirector 1\n"

/// One program being captured: the process httptap started, and httptap's SOCKS5 proxy its flows go to.
struct Capture {
    let pid: pid_t
    let proxy: Network.NWEndpoint
}

/// A server on a Unix socket that keeps, for each connected httptap, the program it captures.
///
/// A client may only capture processes of its own user, unless it is root. When the last client leaves and none
/// comes within the grace period, `onIdle` runs, so the proxy stops while nothing is captured.
final class ControlServer {
    /// How long the server waits without clients before it calls `onIdle`.
    static let idleGrace: TimeInterval = 30
    /// The longest line a client may send.
    static let lineLimit = 1024

    private let listener: Int32
    private let lock = NSLock()
    private var captures: [Int32: Capture] = [:]
    private var idleGeneration = 0
    private var stopped = false
    private let onIdle: () -> Void

    init(onIdle: @escaping () -> Void) throws {
        self.onIdle = onIdle
        unlink(controlSocketPath)
        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = Array(controlSocketPath.utf8CString)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            for (index, byte) in path.prefix(buffer.count - 1).enumerated() {
                buffer[index] = UInt8(bitPattern: byte)
            }
        }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, chmod(controlSocketPath, 0o666) == 0, listen(listener, 16) == 0 else {
            let code = errno
            close(listener)
            throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
        }
        self.listener = listener
    }

    /// Accepts clients on a thread of its own until the listener closes.
    func start() {
        scheduleIdleCheck()
        Thread.detachNewThread { [self] in
            while true {
                let client = accept(listener, nil, nil)
                if client < 0 {
                    if errno == EINTR { continue }
                    return
                }
                Thread.detachNewThread { [self] in serve(client) }
            }
        }
    }

    /// Stops accepting clients and removes the socket, so no httptap can register with a proxy that is stopping.
    func stop() {
        lock.lock()
        let wasStopped = stopped
        stopped = true
        lock.unlock()
        if wasStopped { return }
        unlink(controlSocketPath)
        shutdown(listener, SHUT_RDWR)
        close(listener)
    }

    /// Returns whether the server stopped.
    var isStopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    /// Returns the capture a process belongs to: one whose program is the process or one of its ancestors.
    func capture(forPid pid: pid_t) -> Capture? {
        lock.lock()
        defer { lock.unlock() }
        if captures.isEmpty { return nil }
        let byPid = Dictionary(captures.values.map { ($0.pid, $0) }, uniquingKeysWith: { first, _ in first })
        for ancestor in Processes.lineage(pid) {
            if let capture = byPid[ancestor] { return capture }
        }
        return nil
    }

    /// Serves one client: greets it, takes its `intercept <host> <port> <pid>` lines, and forgets it when it leaves.
    private func serve(_ client: Int32) {
        defer {
            lock.lock()
            captures.removeValue(forKey: client)
            let empty = captures.isEmpty
            lock.unlock()
            close(client)
            if empty { scheduleIdleCheck() }
        }
        var credentials = xucred()
        var size = socklen_t(MemoryLayout<xucred>.size)
        guard getsockopt(client, SOL_LOCAL, LOCAL_PEERCRED, &credentials, &size) == 0 else { return }
        let peer = credentials.cr_uid
        guard write(client, protocolGreeting) else { return }
        var pending = Data()
        var buffer = [UInt8](repeating: 0, count: Self.lineLimit)
        while true {
            let count = read(client, &buffer, buffer.count)
            if count <= 0 { return }
            pending.append(contentsOf: buffer[0..<count])
            while let end = pending.firstIndex(of: UInt8(ascii: "\n")) {
                let line = String(decoding: pending[pending.startIndex..<end], as: UTF8.self)
                pending.removeSubrange(pending.startIndex...end)
                guard write(client, answer(line, client: client, peer: peer)) else { return }
            }
            if pending.count > Self.lineLimit { return }
        }
    }

    /// Carries out one line from a client and returns the line to answer with.
    private func answer(_ line: String, client: Int32, peer: uid_t) -> String {
        let words = line.split(separator: " ").map(String.init)
        guard words.count == 4, words[0] == "intercept", let port = UInt16(words[2]), let pid = pid_t(words[3]),
              let endpointPort = Network.NWEndpoint.Port(rawValue: port)
        else { return "error expected: intercept <host> <port> <pid>\n" }
        guard let owner = Processes.owner(pid) else { return "error no process \(pid)\n" }
        guard peer == 0 || owner == peer else { return "error process \(pid) belongs to another user\n" }
        let capture = Capture(pid: pid, proxy: .hostPort(host: Network.NWEndpoint.Host(words[1]), port: endpointPort))
        lock.lock()
        captures[client] = capture
        lock.unlock()
        log.notice("capturing process \(pid, privacy: .public) through \(words[1], privacy: .public):\(port, privacy: .public)")
        return "ok\n"
    }

    /// Writes all of the text to the client, returning whether it could.
    private func write(_ client: Int32, _ text: String) -> Bool {
        let bytes = Array(text.utf8)
        var written = 0
        while written < bytes.count {
            let count = bytes[written...].withUnsafeBytes { Darwin.write(client, $0.baseAddress, $0.count) }
            if count <= 0 { return false }
            written += count
        }
        return true
    }

    /// Calls `onIdle` after the grace period unless a client registered in the meantime.
    private func scheduleIdleCheck() {
        lock.lock()
        idleGeneration += 1
        let generation = idleGeneration
        lock.unlock()
        DispatchQueue.global().asyncAfter(deadline: .now() + Self.idleGrace) { [self] in
            lock.lock()
            let idle = captures.isEmpty && generation == idleGeneration
            lock.unlock()
            if idle {
                stop()
                onIdle()
            }
        }
    }
}
