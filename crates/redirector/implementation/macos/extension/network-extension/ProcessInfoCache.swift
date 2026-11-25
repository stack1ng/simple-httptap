// Adapted from mitmproxy_rs (MIT, see LICENSE-mitmproxy): processes are matched by ancestry, not by name.

import Foundation

/// Lookups of a process's identity and family through libproc.
enum Processes {
    /// The most ancestors a process is followed up through, which no real process tree reaches.
    static let maxDepth = 64

    /// Returns the process identifier an audit token names.
    static func pid(fromAuditToken tokenData: Data?) -> pid_t? {
        guard let tokenData, tokenData.count == MemoryLayout<audit_token_t>.size else { return nil }
        let token = tokenData.withUnsafeBytes { buffer in
            buffer.baseAddress!.assumingMemoryBound(to: audit_token_t.self).pointee
        }
        return audit_token_to_pid(token)
    }

    /// Returns the BSD information of a process: its parent and its user, among others.
    static func info(_ pid: pid_t) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return info
    }

    /// Returns the process and its ancestors, nearest first, up to but not including launchd.
    static func lineage(_ pid: pid_t) -> [pid_t] {
        var lineage: [pid_t] = []
        var current = pid
        while current > 1, lineage.count < maxDepth {
            lineage.append(current)
            guard let info = info(current) else { break }
            current = pid_t(info.pbi_ppid)
        }
        return lineage
    }

    /// Returns when a process started, in microseconds since 1970, which tells it apart from a later one reusing its identifier.
    static func started(_ info: proc_bsdinfo) -> UInt64 {
        info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec
    }

    /// Returns the process with when it started, or none if it is not running.
    static func identity(_ pid: pid_t) -> ProcessIdentity? {
        info(pid).map { ProcessIdentity(pid: pid, started: started($0)) }
    }

    /// Returns the identifiers of every running process.
    static func all() -> [pid_t] {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(count) * 2)
        let filled = pids.withUnsafeMutableBufferPointer { buffer in
            proc_listallpids(buffer.baseAddress, Int32(buffer.count * MemoryLayout<pid_t>.size))
        }
        return Array(pids.prefix(Int(max(filled, 0)))).filter { $0 > 0 }
    }

    /// Returns the user a process runs as.
    static func owner(_ pid: pid_t) -> uid_t? {
        info(pid).map { $0.pbi_uid }
    }
}
