import Foundation
import Models

/// Collects local group memberships for security-relevant macOS groups.
///
/// Uses `dscl` (Directory Service command line) to enumerate groups and their members.
/// Filters to groups that affect privilege escalation or remote access.
public struct GroupDataSource: DataSource {
    public let name = "Local Groups"
    public let requiresElevation = false

    /// Groups with security-relevant membership. Other groups are noise.
    static let securityRelevantGroups = Set([
        "admin", "wheel", "staff", "_developer",
        "com.apple.access_ssh", "com.apple.access_screensharing",
        "_lpadmin", "com.apple.access_ftp",
    ])

    public init() {}

    public func collect() async -> DataSourceResult {
        var groups: [LocalGroup] = []
        var errors: [CollectionError] = []

        let allGroups = listGroups()
        var allMembers = Set<String>()
        for (groupName, gid) in allGroups {
            guard Self.securityRelevantGroups.contains(groupName) else { continue }
            let members = readGroupMembers(groupName)
            allMembers.formUnion(members)
            groups.append(LocalGroup(name: groupName, gid: gid, members: members))
        }

        if groups.isEmpty {
            errors.append(CollectionError(
                source: "Groups",
                message: "No security-relevant groups found (unexpected on macOS)",
                recoverable: true
            ))
        }

        // Collect extended details for all discovered users
        var userDetails: [UserDetail] = []
        for username in allMembers {
            if let detail = readUserDetail(username) {
                userDetails.append(detail)
            }
        }

        var nodes: [any GraphNode] = groups
        nodes.append(contentsOf: userDetails)
        return DataSourceResult(nodes: nodes, errors: errors)
    }

    // MARK: - Private

    /// Lists all groups as (name, gid) pairs via `dscl . -list /Groups PrimaryGroupID`.
    private func listGroups() -> [(String, Int)] {
        guard let output = Shell.run("/usr/bin/dscl", [
            ".", "-list", "/Groups", "PrimaryGroupID",
        ]) else {
            return []
        }

        var results: [(String, Int)] = []
        for line in output.components(separatedBy: "\n") {
            let parts = line.split(whereSeparator: \.isWhitespace)
            guard parts.count >= 2,
                  let gid = Int(parts[parts.count - 1]) else { continue }
            results.append((String(parts[0]), gid))
        }
        return results
    }

    /// Reads extended user details via a single `dscl . -read /Users/<name>` call.
    private func readUserDetail(_ username: String) -> UserDetail? {
        guard let output = Shell.run("/usr/bin/dscl", [
            ".", "-read", "/Users/\(username)",
            "UserShell", "NFSHomeDirectory", "IsHidden",
        ]) else {
            return nil
        }

        var shell: String?
        var homeDir: String?
        var isHidden = false

        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("UserShell:") {
                shell = String(trimmed.dropFirst("UserShell:".count)).trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("NFSHomeDirectory:") {
                homeDir = String(trimmed.dropFirst("NFSHomeDirectory:".count)).trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("IsHidden:") {
                let value = String(trimmed.dropFirst("IsHidden:".count)).trimmingCharacters(in: .whitespaces)
                isHidden = (value == "1")
            }
        }

        return UserDetail(name: username, shell: shell, homeDir: homeDir, isHidden: isHidden)
    }

    /// Reads the member list for a single group via `dscl . -read /Groups/<name> GroupMembership`.
    private func readGroupMembers(_ groupName: String) -> [String] {
        guard let output = Shell.run("/usr/bin/dscl", [
            ".", "-read", "/Groups/\(groupName)", "GroupMembership",
        ]) else {
            return []
        }

        // Output format: "GroupMembership: user1 user2 user3"
        guard let colonIndex = output.firstIndex(of: ":") else { return [] }
        let membersStr = output[output.index(after: colonIndex)...]
        return membersStr.split(whereSeparator: \.isWhitespace).map(String.init)
    }
}
