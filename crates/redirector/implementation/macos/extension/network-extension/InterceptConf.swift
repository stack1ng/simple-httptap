// The control server httptap processes connect to, one connection per program they capture.
//
// No capture may fail silently: while a client is connected, its program's flows go to its proxy; when the
// connection ends for any reason (httptap exited, crashed or was killed, or this server stopped), every process of
// the program that is still running is stopped, so none of them reaches the network uncaptured.

import Foundation
import Network
import NetworkExtension

/// The path of the control socket, where every httptap process registers the program it captures.
let controlSocketPath = "/var/run/com.stack1ng.simplehttptap.redirector.sock"
/// The first line the server writes to each client, which names the protocol and its version.
let protocolGreeting = "httptap-redirector 2\n"

/// A process told apart from a later one that reuses its identifier, by when it started.
struct ProcessIdentity: Hashable {
    let pid: pid_t
    let started: UInt64
}

/// One program being captured: the process httptap started, httptap's SOCKS5 proxy, and every process known to
/// belong to it, which stays a member after its parent exits and launchd adopts it.
///
/// httptap starts the program as the leader of a process group of its own, so a process is also a member while it
/// is in that group, even one adopted by launchd before it was seen.
struct Capture {
    let program: ProcessIdentity
    let proxy: Network.NWEndpoint
    let client: Int32
    var members: Set<ProcessIdentity>
}

/// A server on a Unix socket that keeps, for each connected httptap, the program it captures.
///
/// A client may only capture processes of its own user, unless it is root. When no client has been connected for
/// the grace period, `onIdle` runs, so the proxy stops while nothing is captured.
final class ControlServer {
    /// How long the server waits without clients before it calls `onIdle`.
    static let idleGrace: TimeInterval = 30
    /// The longest line a client may send.
    static let lineLimit = 1024
    /// How often the process table is read for new members of each capture.
    static let membershipInterval: TimeInterval = 0.25

    private let listener: Int32
    private let lock = NSLock()
    /// Every connected client, with its capture once it registered one.
    private var clients: [Int32: Capture?] = [:]
    private var writeLocks: [Int32: NSLock] = [:]
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
            while !isStopped {
                refreshMembers()
                Thread.sleep(forTimeInterval: Self.membershipInterval)
            }
        }
        Thread.detachNewThread { [self] in
            while true {
                let client = accept(listener, nil, nil)
                if client < 0 {
                    if errno == EINTR { continue }
                    return
                }
                lock.lock()
                if stopped {
                    lock.unlock()
                    close(client)
                    continue
                }
                clients[client] = .some(nil)
                writeLocks[client] = NSLock()
                lock.unlock()
                Thread.detachNewThread { [self] in serve(client) }
            }
        }
    }

    /// Stops accepting clients, removes the socket, and ends every client's connection, which stops its program.
    ///
    /// Each httptap sees its connection end and fails loudly; nothing is left running with its flows uncaptured.
    func stop() {
        lock.lock()
        let wasStopped = stopped
        stopped = true
        let connected = Array(clients.keys)
        lock.unlock()
        if wasStopped { return }
        unlink(controlSocketPath)
        shutdown(listener, SHUT_RDWR)
        close(listener)
        for client in connected {
            shutdown(client, SHUT_RDWR)
        }
    }

    /// Returns whether the server stopped.
    var isStopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    /// Returns the capture a process belongs to: one it, or an ancestor of it, is a member of, adding it as one.
    func capture(forPid pid: pid_t) -> Capture? {
        lock.lock()
        defer { lock.unlock() }
        if stopped { return nil }
        for case let (client, capture?) in clients {
            if Processes.info(pid).map({ $0.pbi_pgid }) == UInt32(capture.program.pid), let identity = Processes.identity(pid) {
                var updated = capture
                updated.members.insert(identity)
                clients[client] = updated
                return updated
            }
            let memberPids = Set(capture.members.map(\.pid))
            let lineage = Processes.lineage(pid)
            guard let index = lineage.firstIndex(where: memberPids.contains),
                  let ancestor = Processes.identity(lineage[index]), capture.members.contains(ancestor)
            else { continue }
            var updated = capture
            for member in lineage[..<index] {
                if let identity = Processes.identity(member) { updated.members.insert(identity) }
            }
            clients[client] = updated
            return updated
        }
        return nil
    }

    /// Adds to each capture every running process descended from one of its members.
    private func refreshMembers() {
        let table = Processes.all().compactMap { pid in Processes.info(pid).map { (pid, $0) } }
        lock.lock()
        defer { lock.unlock() }
        for case let (client, capture?) in clients {
            var updated = capture
            var grew = true
            while grew {
                grew = false
                let memberPids = Set(updated.members.map(\.pid))
                for (pid, info) in table where !memberPids.contains(pid)
                    && (memberPids.contains(pid_t(info.pbi_ppid)) || info.pbi_pgid == UInt32(capture.program.pid)) {
                    updated.members.insert(ProcessIdentity(pid: pid, started: Processes.started(info)))
                    grew = true
                }
            }
            clients[client] = updated
        }
    }

    /// Tells the client that registered the capture that one of its program's flows could not reach its proxy.
    func report(_ capture: Capture, _ detail: String) {
        _ = writeLine(capture.client, "flow-failed \(detail.replacingOccurrences(of: "\n", with: " "))\n")
    }

    /// Serves one client: greets it, carries out its lines, and when it leaves stops what remains of its program.
    private func serve(_ client: Int32) {
        defer {
            lock.lock()
            let capture = clients.removeValue(forKey: client) ?? nil
            writeLocks.removeValue(forKey: client)
            let empty = clients.isEmpty
            lock.unlock()
            close(client)
            if let capture {
                let stopped = Self.stopRemaining(capture)
                if !stopped.isEmpty {
                    log.error("the capture of process \(capture.program.pid, privacy: .public) ended with processes still running; stopped \(stopped.map(String.init).joined(separator: " "), privacy: .public)")
                }
            }
            if empty { scheduleIdleCheck() }
        }
        var credentials = xucred()
        var size = socklen_t(MemoryLayout<xucred>.size)
        guard getsockopt(client, SOL_LOCAL, LOCAL_PEERCRED, &credentials, &size) == 0 else { return }
        let peer = credentials.cr_uid
        guard writeLine(client, protocolGreeting) else { return }
        var pending = Data()
        var buffer = [UInt8](repeating: 0, count: Self.lineLimit)
        while true {
            let count = read(client, &buffer, buffer.count)
            if count <= 0 { return }
            pending.append(contentsOf: buffer[0..<count])
            while let end = pending.firstIndex(of: UInt8(ascii: "\n")) {
                let line = String(decoding: pending[pending.startIndex..<end], as: UTF8.self)
                pending.removeSubrange(pending.startIndex...end)
                guard writeLine(client, answer(line, client: client, peer: peer)) else { return }
            }
            if pending.count > Self.lineLimit { return }
        }
    }

    /// Carries out one line from a client and returns the line to answer with.
    ///
    /// `intercept <host> <port> <pid>` registers the program; `end` stops what remains of it and names what it
    /// stopped, after the program itself exited.
    private func answer(_ line: String, client: Int32, peer: uid_t) -> String {
        let words = line.split(separator: " ").map(String.init)
        if words == ["end"] {
            lock.lock()
            let capture = clients[client] ?? nil
            clients[client] = .some(nil)
            lock.unlock()
            let stopped = capture.map(Self.stopRemaining) ?? []
            return "ended" + stopped.map { " \($0)" }.joined() + "\n"
        }
        guard words.count == 4, words[0] == "intercept", let port = UInt16(words[2]), let pid = pid_t(words[3]),
              let endpointPort = Network.NWEndpoint.Port(rawValue: port)
        else { return "error expected: intercept <host> <port> <pid>, or end\n" }
        guard let identity = Processes.identity(pid), let owner = Processes.owner(pid) else { return "error no process \(pid)\n" }
        guard peer == 0 || owner == peer else { return "error process \(pid) belongs to another user\n" }
        let capture = Capture(program: identity, proxy: .hostPort(host: Network.NWEndpoint.Host(words[1]), port: endpointPort), client: client, members: [identity])
        lock.lock()
        if stopped {
            lock.unlock()
            return "error the proxy is stopping\n"
        }
        clients[client] = capture
        lock.unlock()
        log.notice("capturing process \(pid, privacy: .public) through \(words[1], privacy: .public):\(port, privacy: .public)")
        return "ok\n"
    }

    /// Stops, with SIGKILL, every member of the capture still running and their descendants; returns their identifiers.
    private static func stopRemaining(_ capture: Capture) -> [pid_t] {
        let living = Set(capture.members.filter { Processes.identity($0.pid) == $0 }.map(\.pid))
        var doomed = living
        for pid in Processes.all() where !doomed.contains(pid) {
            let inGroup = Processes.info(pid).map { $0.pbi_pgid } == UInt32(capture.program.pid)
            if inGroup || Processes.lineage(pid).contains(where: living.contains) { doomed.insert(pid) }
        }
        for pid in doomed {
            kill(pid, SIGKILL)
        }
        return doomed.sorted()
    }

    /// Writes all of the text to the client, one writer at a time, returning whether it could.
    private func writeLine(_ client: Int32, _ text: String) -> Bool {
        lock.lock()
        let writeLock = writeLocks[client]
        lock.unlock()
        guard let writeLock else { return false }
        writeLock.lock()
        defer { writeLock.unlock() }
        let bytes = Array(text.utf8)
        var written = 0
        while written < bytes.count {
            let count = bytes[written...].withUnsafeBytes { Darwin.write(client, $0.baseAddress, $0.count) }
            if count <= 0 { return false }
            written += count
        }
        return true
    }

    /// Calls `onIdle` after the grace period unless a client connected in the meantime.
    private func scheduleIdleCheck() {
        lock.lock()
        idleGeneration += 1
        let generation = idleGeneration
        lock.unlock()
        DispatchQueue.global().asyncAfter(deadline: .now() + Self.idleGrace) { [self] in
            lock.lock()
            let idle = clients.isEmpty && generation == idleGeneration
            lock.unlock()
            if idle {
                stop()
                onIdle()
            }
        }
    }
}
