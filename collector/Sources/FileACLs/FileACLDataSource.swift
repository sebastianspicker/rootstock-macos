import Foundation
import Models
import FileACLInspection
import RootstockMacFacts

/// Collects file permissions for security-critical paths on macOS.
///
/// Scans a defined set of critical paths (TCC databases, keychains, sudoers,
/// sshd_config, LaunchAgent/Daemon directories, authorization DB) and reports
/// ownership, permissions, ACL entries, and writability by non-root users.
public struct FileACLDataSource: DataSource {
    public let name = "File ACLs"
    public let requiresElevation = false
    private let inspector: FileACLInspector

    /// Critical paths to check, grouped by semantic category.
    /// A trailing "/" marks a directory whose `*.plist` entries are also checked.
    static let criticalPaths: [(path: String, category: String)] = [
        // TCC databases
        ("~/" + MacSecurityPaths.userTCCDatabaseRelative, "tcc_database"),
        (MacSecurityPaths.systemTCCDatabase, "tcc_database"),
        // Keychain files
        ("~/Library/Keychains/login.keychain-db", "keychain"),
        ("/Library/Keychains/System.keychain", "keychain"),
        // Sudoers configuration
        (MacSecurityPaths.sudoers, "sudoers"),
        // SSH configuration
        ("/etc/ssh/sshd_config", "ssh_config"),
        // LaunchAgent/Daemon directories
        ("~/" + MacSecurityPaths.userLaunchAgentsRelative + "/", "launch_agent_dir"),
        (MacSecurityPaths.systemLaunchDaemons + "/", "launch_daemon_dir"),
        (MacSecurityPaths.systemLaunchAgents + "/", "launch_agent_dir"),
        // Authorization database
        ("/etc/authorization", "authorization_db"),
    ]

    public init() {
        inspector = FileACLInspector()
    }

    init(readACLEntries: @escaping (String) -> (entries: [String], error: String?)) {
        inspector = FileACLInspector(readACLEntries: readACLEntries)
    }

    public func collect() async -> DataSourceResult {
        var results: [FileACL] = []
        var errors: [CollectionError] = []
        let fm = FileManager.default

        for (rawPath, category) in Self.criticalPaths {
            collectCriticalPath(
                rawPath,
                category: category,
                fm: fm,
                results: &results,
                errors: &errors
            )

            // Handle sudoers.d include directory
            if rawPath == MacSecurityPaths.sudoers {
                collectSudoersIncludes(fm: fm, results: &results, errors: &errors)
            }
        }

        return DataSourceResult(nodes: results, errors: errors)
    }

    // MARK: - Internal

    private func collectCriticalPath(
        _ rawPath: String,
        category: String,
        fm: FileManager,
        results: inout [FileACL],
        errors: inout [CollectionError]
    ) {
        let path = FileACLInspector.expandTilde(rawPath)
        appendCollectedPath(path, category: category, fm: fm, results: &results, errors: &errors)

        if rawPath.hasSuffix("/") {
            collectPlistEntries(in: path, category: category, fm: fm, results: &results, errors: &errors)
        }
    }

    private func collectPlistEntries(
        in directory: String,
        category: String,
        fm: FileManager,
        results: inout [FileACL],
        errors: inout [CollectionError]
    ) {
        guard let entries = (try? fm.contentsOfDirectory(atPath: directory))?.sorted() else {
            return
        }

        for entry in entries where entry.hasSuffix(".plist") {
            let filePath = (directory as NSString).appendingPathComponent(entry)
            appendCollectedPath(filePath, category: category, fm: fm, results: &results, errors: &errors)
        }
    }

    private func collectSudoersIncludes(
        fm: FileManager,
        results: inout [FileACL],
        errors: inout [CollectionError]
    ) {
        let sudoersD = MacSecurityPaths.sudoersD
        guard fm.fileExists(atPath: sudoersD),
              let files = (try? fm.contentsOfDirectory(atPath: sudoersD))?.sorted() else {
            return
        }

        for file in files where !file.hasPrefix(".") {
            let filePath = (sudoersD as NSString).appendingPathComponent(file)
            appendCollectedPath(filePath, category: "sudoers", fm: fm, results: &results, errors: &errors)
        }
    }

    private func appendCollectedPath(
        _ path: String,
        category: String,
        fm: FileManager,
        results: inout [FileACL],
        errors: inout [CollectionError]
    ) {
        let (acl, error) = inspector.collectPath(path, category: category, fm: fm)
        if let acl {
            results.append(acl)
        }
        if let error {
            errors.append(CollectionError(source: name, message: error, recoverable: true))
        }
    }
}
