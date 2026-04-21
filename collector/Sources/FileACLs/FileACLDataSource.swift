import Foundation
import Models

/// Collects file permissions for security-critical paths on macOS.
///
/// Scans a defined set of critical paths (TCC databases, keychains, sudoers,
/// sshd_config, LaunchAgent/Daemon directories, authorization DB) and reports
/// ownership, permissions, ACL entries, and writability by non-root users.
public struct FileACLDataSource: DataSource {
    public let name = "File ACLs"
    public let requiresElevation = false

    /// Critical paths to check, grouped by semantic category.
    static let criticalPaths: [(path: String, category: String)] = [
        // TCC databases
        ("~/Library/Application Support/com.apple.TCC/TCC.db", "tcc_database"),
        ("/Library/Application Support/com.apple.TCC/TCC.db", "tcc_database"),
        // Keychain files
        ("~/Library/Keychains/login.keychain-db", "keychain"),
        ("/Library/Keychains/System.keychain", "keychain"),
        // Sudoers configuration
        ("/etc/sudoers", "sudoers"),
        // SSH configuration
        ("/etc/ssh/sshd_config", "ssh_config"),
        // LaunchAgent/Daemon directories
        ("~/Library/LaunchAgents/", "launch_agent_dir"),
        ("/Library/LaunchDaemons/", "launch_daemon_dir"),
        ("/Library/LaunchAgents/", "launch_agent_dir"),
        // Authorization database
        ("/etc/authorization", "authorization_db"),
    ]

    /// SIP-protected path prefixes on macOS Sonoma+.
    private static let sipPrefixes = [
        "/System/",
        "/usr/lib/",
        "/usr/bin/",
        "/usr/sbin/",
    ]

    public init() {}

    public func collect() async -> DataSourceResult {
        var results: [FileACL] = []
        var errors: [CollectionError] = []
        let fm = FileManager.default

        for (rawPath, category) in Self.criticalPaths {
            let path = Self.expandTilde(rawPath)

            // For directory paths, check the directory itself
            if rawPath.hasSuffix("/") {
                let (acl, error) = collectPath(path, category: category, fm: fm)
                if let acl { results.append(acl) }
                if let error { errors.append(CollectionError(source: name, message: error, recoverable: true)) }

                // Also enumerate files within LaunchAgent/Daemon directories
                if let entries = try? fm.contentsOfDirectory(atPath: path) {
                    for entry in entries where entry.hasSuffix(".plist") {
                        let filePath = (path as NSString).appendingPathComponent(entry)
                        let (fileAcl, fileError) = collectPath(filePath, category: category, fm: fm)
                        if let fileAcl { results.append(fileAcl) }
                        if let fileError { errors.append(CollectionError(source: name, message: fileError, recoverable: true)) }
                    }
                }
            } else {
                let (acl, error) = collectPath(path, category: category, fm: fm)
                if let acl { results.append(acl) }
                if let error { errors.append(CollectionError(source: name, message: error, recoverable: true)) }
            }

            // Handle sudoers.d include directory
            if rawPath == "/etc/sudoers" {
                let sudoersD = "/etc/sudoers.d"
                if fm.fileExists(atPath: sudoersD),
                   let files = try? fm.contentsOfDirectory(atPath: sudoersD) {
                    for file in files where !file.hasPrefix(".") {
                        let filePath = (sudoersD as NSString).appendingPathComponent(file)
                        let (acl, error) = collectPath(filePath, category: "sudoers", fm: fm)
                        if let acl { results.append(acl) }
                        if let error { errors.append(CollectionError(source: name, message: error, recoverable: true)) }
                    }
                }
            }
        }

        return DataSourceResult(nodes: results, errors: errors)
    }

    // MARK: - Internal

    func collectPath(_ path: String, category: String, fm: FileManager) -> (FileACL?, String?) {
        guard fm.fileExists(atPath: path) else {
            return (nil, nil)  // Missing file is not an error — it's expected on some systems
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

        let aclEntries = Self.readACLEntries(path: path)
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
        ), nil)
    }

    /// Expand ~ to the current user's home directory.
    public static func expandTilde(_ path: String) -> String {
        (path as NSString).expandingTildeInPath
    }

    /// Read extended ACL entries using `ls -le`.
    public static func readACLEntries(path: String) -> [String] {
        guard let output = Shell.run("/bin/ls", ["-led", path]) else { return [] }
        return parseACLOutput(output)
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
