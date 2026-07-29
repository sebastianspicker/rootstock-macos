import Foundation
import Models

/// Detects Active Directory binding status and AD-to-local group mappings.
///
/// Runs `dsconfigad -show` and diffs `dscl /Search` vs `dscl .` user lists
/// to find network (AD) users.  Returns `isBound: false` gracefully on
/// non-AD-bound Macs - this is not an error condition.
///
/// No elevation required: `dsconfigad -show` and `dscl` read operations
/// work without root.
public struct ActiveDirectoryDataSource: DataSource {
    public let name = "Active Directory"
    public let requiresElevation = false
    private let runCommand: ShellCommand

    public init() {
        runCommand = { path, arguments, timeout in
            ShellCommandRunner.run(path, arguments, timeout)
        }
    }

    init(
        runCommand: @escaping ShellCommand
    ) {
        self.runCommand = runCommand
    }

    /// Groups worth checking for AD-sourced membership (matches GroupDataSource).
    static let securityRelevantGroups = [
        "_developer", "wheel", "staff",
        "com.apple.access_ssh", "com.apple.access_screensharing",
        "_lpadmin", "com.apple.access_ftp",
    ]

    public func collect() async -> DataSourceResult {
        collectWithBinding().result
    }

    /// Collect AD data and binding info in a single pass (avoids running dsconfigad twice).
    public func collectWithBinding() -> (result: DataSourceResult, binding: ADBinding) {
        let outcome = collectWithBindingOutcome()
        return (outcome.result, outcome.binding ?? ADBinding(isBound: false))
    }

    /// Collect AD data while preserving unknown binding status after a command failure.
    public func collectWithBindingOutcome() -> (result: DataSourceResult, binding: ADBinding?) {
        var errors: [CollectionError] = []

        let binding = parseBinding(errors: &errors)
        let networkUsers = binding?.isBound == true ? detectNetworkUsers(errors: &errors) : []

        var nodes: [any GraphNode] = []
        for username in networkUsers {
            nodes.append(UserDetail(
                name: username,
                shell: nil,
                homeDir: nil,
                isHidden: false,
                isADUser: true
            ))
        }

        // Discover AD-sourced members in non-admin local groups.
        // GroupDataSource uses `dscl .` which misses AD-granted memberships.
        if binding?.isBound == true {
            let adGroups = discoverADGroupMemberships(errors: &errors)
            nodes.append(contentsOf: adGroups)
        }

        return (DataSourceResult(nodes: nodes, errors: errors), binding)
    }

    /// The parsed AD binding result for the orchestrator to read directly.
    /// Prefer `collectWithBinding()` to avoid running dsconfigad twice.
    public func collectBinding() -> ADBinding {
        collectBindingOutcome() ?? ADBinding(isBound: false)
    }

    /// Reads AD binding status while preserving an unknown result after command failure.
    public func collectBindingOutcome() -> ADBinding? {
        var errors: [CollectionError] = []
        return parseBinding(errors: &errors)
    }

    // MARK: - Internal parsing (visible for testing)

    /// Parse `dsconfigad -show` output into an ADBinding.
    func parseBinding(errors: inout [CollectionError]) -> ADBinding? {
        let outcome = runCommand("/usr/sbin/dsconfigad", ["-show"], 15)
        guard case .success(let result) = outcome else {
            errors.append(commandError(
                "Active Directory binding status is unknown",
                outcome: outcome
            ))
            return nil
        }
        return parseDsconfigadOutput(result.stdout)
    }

    /// Parse the raw text output of `dsconfigad -show`.
    func parseDsconfigadOutput(_ output: String) -> ADBinding {
        var values: [String: String] = [:]
        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let eqRange = trimmed.range(of: "=") else { continue }
            let key = trimmed[trimmed.startIndex..<eqRange.lowerBound]
                .trimmingCharacters(in: .whitespaces)
            let value = trimmed[eqRange.upperBound...]
                .trimmingCharacters(in: .whitespaces)
            guard !value.isEmpty else { continue }
            values[key] = value
        }

        // If there's no "Active Directory Domain" or "Active Directory Forest",
        // the Mac is not bound.
        guard values["Active Directory Domain"] != nil || values["Active Directory Forest"] != nil else {
            return ADBinding(isBound: false)
        }

        let groupMappings = parseGroupMappings(values["Allowed admin groups"])

        return ADBinding(
            isBound: true,
            realm: values["Active Directory Domain"],
            forest: values["Active Directory Forest"],
            computerAccount: values["Computer Account"],
            organizationalUnit: values["Organizational Unit"],
            preferredDC: values["Preferred Domain Controller"],
            groupMappings: groupMappings
        )
    }

    /// Parse comma-separated admin groups into ADGroupMapping entries.
    /// Each AD group listed is mapped to the local "admin" group.
    func parseGroupMappings(_ raw: String?) -> [ADGroupMapping] {
        guard let raw = raw, !raw.isEmpty else { return [] }
        return raw
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .map { ADGroupMapping(adGroup: $0, localGroup: "admin") }
    }

    /// Discover AD-sourced members in security-relevant local groups by diffing
    /// `dscl /Search` vs `dscl .` group membership.  Returns LocalGroup nodes
    /// whose members include only the AD-sourced users (the import layer MERGEs
    /// these with existing LocalGroup nodes from GroupDataSource).
    func discoverADGroupMemberships(errors: inout [CollectionError]) -> [LocalGroup] {
        var results: [LocalGroup] = []
        for groupName in Self.securityRelevantGroups {
            let adMembers = diffGroupMembership(groupName, errors: &errors)
            guard !adMembers.isEmpty else { continue }
            // GID 0 is a placeholder - the real GID comes from GroupDataSource.
            // The import layer's CASE expression preserves non-zero GIDs,
            // so the GroupDataSource's real GID is never overwritten by this placeholder.
            results.append(LocalGroup(name: groupName, gid: 0, members: adMembers))
        }
        return results
    }

    /// Returns members present in `/Search` but not in `.` for a given group.
    func diffGroupMembership(
        _ groupName: String,
        errors: inout [CollectionError]
    ) -> [String] {
        let searchMembers = readGroupMembers(
            node: "/Search",
            groupName: groupName,
            errors: &errors
        )
        let localMembers = readGroupMembers(
            node: ".",
            groupName: groupName,
            errors: &errors
        )
        return Set(searchMembers).subtracting(localMembers).sorted()
    }

    /// Read the member list for a group from a specific directory node.
    private func readGroupMembers(
        node: String,
        groupName: String,
        errors: inout [CollectionError]
    ) -> [String] {
        let outcome = runCommand("/usr/bin/dscl", [
            node, "-read", "/Groups/\(groupName)", "GroupMembership",
        ], 15)
        guard case .success(let result) = outcome else {
            if case .nonZeroExit(let result) = outcome,
               isExpectedMissingDirectoryRecord(result) {
                return []
            }
            errors.append(commandError(
                "AD membership is unknown for \(node)/Groups/\(groupName)",
                outcome: outcome
            ))
            return []
        }
        return LocalGroup.members(inDirectoryServiceOutput: result.stdout)
    }

    /// Detect network (AD) users by diffing /Search vs local user lists.
    func detectNetworkUsers(errors: inout [CollectionError]) -> [String] {
        let searchOutcome = runCommand(
            "/usr/bin/dscl",
            ["/Search", "-list", "/Users"],
            15
        )
        let localOutcome = runCommand(
            "/usr/bin/dscl",
            [".", "-list", "/Users"],
            15
        )
        guard case .success(let searchResult) = searchOutcome,
              case .success(let localResult) = localOutcome else {
            if case .success = searchOutcome {
                errors.append(commandError(
                    "Local user enumeration is unknown",
                    outcome: localOutcome
                ))
            } else {
                errors.append(commandError(
                    "Directory search user enumeration is unknown",
                    outcome: searchOutcome
                ))
            }
            return []
        }
        return parseNetworkUsers(
            searchOutput: searchResult.stdout,
            localOutput: localResult.stdout
        )
    }

    /// Given `dscl /Search -list /Users` and `dscl . -list /Users` output,
    /// return usernames present in /Search but not in local.
    func parseNetworkUsers(searchOutput: String, localOutput: String) -> [String] {
        let searchSet = Set(searchOutput.components(separatedBy: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty })
        let localSet = Set(localOutput.components(separatedBy: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty })
        return searchSet.subtracting(localSet).sorted()
    }

    private func commandError(
        _ context: String,
        outcome: ShellOutcome
    ) -> CollectionError {
        CollectionError(
            source: name,
            message: "\(context): \(outcome.failureDescription ?? "command failure")",
            recoverable: true
        )
    }

    private func isExpectedMissingDirectoryRecord(_ result: ShellResult) -> Bool {
        let output = "\(result.stdout)\n\(result.stderr)".lowercased()
        return output.contains("edsrecordnotfound")
            || output.contains("edsattributenotfound")
            || output.contains("no such key")
    }
}
