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

    /// Returns the user a process runs as.
    static func owner(_ pid: pid_t) -> uid_t? {
        info(pid).map { $0.pbi_uid }
    }
}
