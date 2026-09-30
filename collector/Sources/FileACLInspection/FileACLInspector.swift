import Foundation
import Models
import HostCommand

/// Reads ownership, POSIX permissions, and extended ACL entries for a single path.
///
/// Shared by the File ACLs and Shell Hooks data sources so that neither data
/// source depends on the other.
public struct FileACLInspector {
    private let readACLEntries: (String) -> (entries: [String], error: String?)

    /// SIP-protected path prefixes on macOS Sonoma+.
    private static let sipPrefixes = [
        "/System/",
        "/usr/lib/",
        "/usr/bin/",
        "/usr/sbin/",
    ]

    public init() {
        readACLEntries = Self.readACLEntriesWithDiagnostic
    }

    public init(readACLEntries: @escaping (String) -> (entries: [String], error: String?)) {
        self.readACLEntries = readACLEntries
    }

    public func collectPath(
        _ path: String,
        category: String,
        fm: FileManager,
        reportsACLErrors: Bool = true
    ) -> (FileACL?, String?) {
        guard fm.fileExists(atPath: path) else {
            return (nil, nil)  // Missing file is not an error - it's expected on some systems
        }

        let attrs: [FileAttributeKey: Any]
        do {
            attrs = try fm.attributesOfItem(atPath: path)
        } catch {
            return (nil, "Cannot read attributes of \(path): \(error.localizedDescription)")
        }

        let owner = attrs[.ownerAccountName] as? String ?? "unknown"
        let group = attrs[.groupOwnerAccountName] as? String ?? "unknown"
        let posixPerms = attrs[.posixPermissions] as? Int ?? 0
        let mode = String(format: "%o", posixPerms)

        let aclResult = readACLEntries(path)
        let aclEntries = aclResult.entries
        let isSipProtected = Self.isSIPProtected(path)
        let isWritableByNonRoot = Self.checkWritableByNonRoot(posixPerms: posixPerms, owner: owner, aclEntries: aclEntries)

        return (FileACL(
            path: path,
            owner: owner,
            group: group,
            mode: mode,
            aclEntries: aclEntries,
            isSipProtected: isSipProtected,
            isWritableByNonRoot: isWritableByNonRoot,
            category: category
        ), reportsACLErrors ? aclResult.error : nil)
    }

    /// Expand ~ to the current user's home directory.
    public static func expandTilde(_ path: String) -> String {
        (path as NSString).expandingTildeInPath
    }

    /// Read extended ACL entries using `ls -le`.
    public static func readACLEntries(path: String) -> [String] {
        readACLEntriesWithDiagnostic(path: path).entries
    }

    private static func readACLEntriesWithDiagnostic(
        path: String
    ) -> (entries: [String], error: String?) {
        let outcome = Shell.execute("/bin/ls", ["-led", path])
        guard case .success(let result) = outcome else {
            return (
                [],
                "Cannot read ACL entries for \(path): \(outcome.failureDescription ?? "command failure")"
            )
        }
        return (parseACLOutput(result.stdout), nil)
    }

    /// Parse ACL entries from `ls -le` output.
    internal static func parseACLOutput(_ output: String) -> [String] {
        var entries: [String] = []
        let lines = output.split(separator: "\n", omittingEmptySubsequences: false)
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // ACL entries in ls -le output are indented lines starting with a number followed by ":"
            if trimmed.first?.isNumber == true, trimmed.contains(":") {
                // Strip the leading "N: " prefix
                if let colonRange = trimmed.range(of: ": ") {
                    entries.append(String(trimmed[colonRange.upperBound...]))
                }
            }
        }
        return entries
    }

    /// Check if a path is under SIP protection based on known prefixes.
    internal static func isSIPProtected(_ path: String) -> Bool {
        sipPrefixes.contains { path.hasPrefix($0) }
    }

    /// Determine if a file is writable by a non-root user.
    /// Checks: world-writable bit (o+w), group-writable if group is not wheel/admin,
    /// or explicit ACL write grants.
    public static func checkWritableByNonRoot(posixPerms: Int, owner: String, aclEntries: [String]) -> Bool {
        // World-writable (others write bit)
        if posixPerms & 0o002 != 0 {
            return true
        }

        // Owner is not root but has write permission
        if owner != "root" && posixPerms & 0o200 != 0 {
            return true
        }

        // ACL grants write to non-root
        for entry in aclEntries {
            let lower = entry.lowercased()
            if lower.contains("allow") && lower.contains("write") {
                return true
            }
        }

        return false
    }
}
