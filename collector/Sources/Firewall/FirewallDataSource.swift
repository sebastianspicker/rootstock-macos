import Foundation
import HostCommand
import Models

/// Collects macOS Application Firewall (ALF) status and per-app rules.
///
/// Primary source is `/usr/libexec/ApplicationFirewall/socketfilterfw`, which works
/// unprivileged and is the supported interface on macOS 15+ where
/// `/Library/Preferences/com.apple.alf.plist` no longer exists. The plist is kept
/// as a fallback for older systems.
public struct FirewallDataSource: DataSource {
    public let name = "Firewall"
    public let requiresElevation = false

    static let socketFilterFWPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    private let alfPlistPath: String
    private let runCommand: ShellCommand
    struct ALFParseResult {
        let status: FirewallStatus
        let errors: [CollectionError]
    }

    public init(alfPlistPath: String = "/Library/Preferences/com.apple.alf.plist") {
        self.alfPlistPath = alfPlistPath
        self.runCommand = { path, arguments, timeout in
            ShellCommandRunner.run(path, arguments, timeout)
        }
    }

    init(
        alfPlistPath: String = "/Library/Preferences/com.apple.alf.plist",
        runCommand: @escaping ShellCommand
    ) {
        self.alfPlistPath = alfPlistPath
        self.runCommand = runCommand
    }

    public func collect() async -> DataSourceResult {
        let live = collectFromSocketFilterFW()
        if live.anyDataCollected {
            return DataSourceResult(nodes: [live.status], errors: live.errors)
        }

        var errors: [CollectionError] = []
        guard let plistData = try? Data(contentsOf: URL(fileURLWithPath: alfPlistPath)),
              let plist = try? PropertyListSerialization.propertyList(
                   from: plistData, format: nil
               ) as? [String: Any] else {
            errors.append(contentsOf: live.errors)
            errors.append(CollectionError(
                source: "Firewall",
                message: "Could not read ALF preferences at \(alfPlistPath)",
                recoverable: true
            ))
            let unknown = FirewallStatus(
                enabled: nil, stealthMode: nil,
                allowSigned: nil, allowBuiltIn: nil, appRules: []
            )
            return DataSourceResult(nodes: [unknown], errors: errors)
        }

        let parsed = parseALFPlistWithDiagnostics(plist)
        errors.append(contentsOf: parsed.errors)
        return DataSourceResult(nodes: [parsed.status], errors: errors)
    }

    // MARK: - socketfilterfw

    private struct LiveResult {
        let status: FirewallStatus
        let errors: [CollectionError]
        let anyDataCollected: Bool
    }

    private func collectFromSocketFilterFW() -> LiveResult {
        var errors: [CollectionError] = []

        func output(_ flag: String) -> String? {
            let arguments = [flag]
            let command = "\(Self.socketFilterFWPath) \(flag)"
            let outcome = runCommand(
                Self.socketFilterFWPath, arguments, Shell.defaultTimeoutSeconds
            )
            guard case .success(let result) = outcome else {
                errors.append(CollectionError(
                    source: "Firewall",
                    message: "\(command) failed: \(outcome.failureDescription ?? "command failure")",
                    recoverable: true
                ))
                return nil
            }
            return result.stdout
        }

        func unparseable(_ flag: String, _ text: String) {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            errors.append(CollectionError(
                source: "Firewall",
                message: "\(Self.socketFilterFWPath) \(flag) returned unparseable output: \(trimmed)",
                recoverable: true
            ))
        }

        var state: Bool?
        if let text = output("--getglobalstate") {
            state = Self.parseGlobalState(text)
            if state == nil { unparseable("--getglobalstate", text) }
        }
        var stealth: Bool?
        if let text = output("--getstealthmode") {
            stealth = Self.parseStealthMode(text)
            if stealth == nil { unparseable("--getstealthmode", text) }
        }
        var allowBuiltIn: Bool?
        var allowSigned: Bool?
        if let text = output("--getallowsigned") {
            let parsed = Self.parseAllowSigned(text)
            allowBuiltIn = parsed.builtIn
            allowSigned = parsed.downloaded
            if allowBuiltIn == nil && allowSigned == nil { unparseable("--getallowsigned", text) }
        }
        var blockAll: Bool?
        if let text = output("--getblockall") {
            blockAll = Self.parseBlockAll(text)
            if blockAll == nil { unparseable("--getblockall", text) }
        }
        var appRules: [FirewallAppRule] = []
        var listAppsOK = false
        if let text = output("--listapps") {
            if text.lowercased().contains("total number of apps") {
                appRules = Self.parseListApps(text)
                listAppsOK = true
            } else {
                unparseable("--listapps", text)
            }
        }

        // Block-all (global state 2) implies the firewall is enabled. The model has no
        // separate block-all field, so it is folded into `enabled`.
        let enabled: Bool?
        if blockAll == true {
            enabled = true
        } else {
            enabled = state
        }

        let anyData = state != nil || stealth != nil || allowBuiltIn != nil
            || allowSigned != nil || blockAll != nil || listAppsOK
        return LiveResult(
            status: FirewallStatus(
                enabled: enabled,
                stealthMode: stealth,
                allowSigned: allowSigned,
                allowBuiltIn: allowBuiltIn,
                appRules: appRules
            ),
            errors: errors,
            anyDataCollected: anyData
        )
    }

    /// Parses `--getglobalstate`: "Firewall is enabled. (State = 1)". State 2 is block-all.
    static func parseGlobalState(_ output: String) -> Bool? {
        let lowered = output.lowercased()
        if let range = lowered.range(of: "state = ") {
            let digits = lowered[range.upperBound...].prefix { $0.isNumber }
            if let value = Int(digits) { return value > 0 }
        }
        if lowered.contains("disabled") { return false }
        if lowered.contains("enabled") { return true }
        return nil
    }

    /// Parses `--getstealthmode`: "Firewall stealth mode is on|off".
    static func parseStealthMode(_ output: String) -> Bool? {
        let lowered = output.lowercased()
        if lowered.contains("is off") || lowered.contains("disabled") { return false }
        if lowered.contains("is on") || lowered.contains("enabled") { return true }
        return nil
    }

    /// Parses `--getallowsigned` (built-in line, then downloaded line).
    static func parseAllowSigned(_ output: String) -> (builtIn: Bool?, downloaded: Bool?) {
        var builtIn: Bool?
        var downloaded: Bool?
        for line in output.lowercased().split(whereSeparator: \.isNewline) {
            let value: Bool?
            if line.contains("disabled") {
                value = false
            } else if line.contains("enabled") {
                value = true
            } else {
                value = nil
            }
            if line.contains("built-in") {
                builtIn = value
            } else if line.contains("downloaded") {
                downloaded = value
            }
        }
        return (builtIn, downloaded)
    }

    /// Parses `--getblockall`: "Firewall has block all state set to enabled|disabled."
    static func parseBlockAll(_ output: String) -> Bool? {
        let lowered = output.lowercased()
        if lowered.contains("disabled") { return false }
        if lowered.contains("enabled") { return true }
        return nil
    }

    /// Parses `--listapps` entries: "1 :  /Applications/Foo.app" followed by
    /// "( Allow incoming connections )" or "( Block incoming connections )".
    static func parseListApps(_ output: String) -> [FirewallAppRule] {
        var rules: [FirewallAppRule] = []
        var currentPath: String?
        var currentAllow: Bool?

        func flush() {
            if let path = currentPath {
                rules.append(FirewallAppRule(
                    bundleId: bundleIdentifier(forAppAt: path) ?? path,
                    allowIncoming: currentAllow
                ))
            }
            currentPath = nil
            currentAllow = nil
        }

        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if let separator = line.range(of: " :"),
               !line.isEmpty,
               line[line.startIndex..<separator.lowerBound].allSatisfy(\.isNumber),
               !line[line.startIndex..<separator.lowerBound].isEmpty {
                flush()
                let path = line[separator.upperBound...].trimmingCharacters(in: .whitespaces)
                currentPath = path.isEmpty ? nil : path
            } else if currentPath != nil {
                let lowered = line.lowercased()
                if lowered.contains("allow incoming") {
                    currentAllow = true
                } else if lowered.contains("block incoming") {
                    currentAllow = false
                }
            }
        }
        flush()
        return rules
    }

    /// Reads `CFBundleIdentifier` from `<path>/Contents/Info.plist` for `.app` bundles.
    private static func bundleIdentifier(forAppAt path: String) -> String? {
        guard path.hasSuffix(".app") else { return nil }
        let infoPath = (path as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = try? BoundedFileReader.read(path: infoPath),
              let plist = try? PropertyListSerialization.propertyList(
                  from: data, format: nil
              ) as? [String: Any],
              let identifier = plist["CFBundleIdentifier"] as? String,
              !identifier.isEmpty else { return nil }
        return identifier
    }

    // MARK: - ALF plist (fallback)

    /// Parses the ALF plist dictionary into a FirewallStatus.
    func parseALFPlist(_ plist: [String: Any]) -> FirewallStatus {
        parseALFPlistWithDiagnostics(plist).status
    }

    /// Parses the ALF plist dictionary and reports missing fields as unknown.
    func parseALFPlistWithDiagnostics(_ plist: [String: Any]) -> ALFParseResult {
        var errors: [CollectionError] = []

        // globalstate: 0=off, 1=on (specific services), 2=essential only
        let enabled = intValue("globalstate", from: plist, errors: &errors).map { $0 > 0 }
        let stealthMode = intValue("stealthenabled", from: plist, errors: &errors).map { $0 != 0 }
        // allowsignedenabled: automatically allow built-in signed software
        let allowBuiltIn = intValue("allowsignedenabled", from: plist, errors: &errors).map { $0 != 0 }

        // allowdownloadsignedenabled: automatically allow downloaded signed software
        let allowSigned = intValue("allowdownloadsignedenabled", from: plist, errors: &errors).map { $0 != 0 }
        let appRules = appRules(from: plist, errors: &errors)

        return ALFParseResult(
            status: FirewallStatus(
                enabled: enabled,
                stealthMode: stealthMode,
                allowSigned: allowSigned,
                allowBuiltIn: allowBuiltIn,
                appRules: appRules
            ),
            errors: errors
        )
    }

    private func intValue(
        _ key: String,
        from plist: [String: Any],
        errors: inout [CollectionError]
    ) -> Int? {
        if let value = plist[key] as? Int {
            return value
        }
        if plist.keys.contains(key) {
            errors.append(CollectionError(
                source: "Firewall",
                message: "ALF preference key '\(key)' is not an integer",
                recoverable: true
            ))
        } else {
            errors.append(CollectionError(
                source: "Firewall",
                message: "ALF preference key '\(key)' is missing; state is unknown",
                recoverable: true
            ))
        }
        return nil
    }

    private func appRules(
        from plist: [String: Any],
        errors: inout [CollectionError]
    ) -> [FirewallAppRule] {
        guard let apps = plist["applications"] as? [[String: Any]] else {
            appendApplicationsTypeErrorIfPresent(plist, errors: &errors)
            return []
        }
        return apps.compactMap { appRule(from: $0, errors: &errors) }
    }

    private func appRule(
        from app: [String: Any],
        errors: inout [CollectionError]
    ) -> FirewallAppRule? {
        guard let bundleID = app["bundleid"] as? String else { return nil }
        // state: 3 = allow incoming, 4 = block incoming
        let state = app["state"] as? Int
        if state == nil {
            errors.append(CollectionError(
                source: "Firewall",
                message: "ALF application rule for \(bundleID) is missing 'state'; allow_incoming is unknown",
                recoverable: true
            ))
        }
        return FirewallAppRule(
            bundleId: bundleID,
            allowIncoming: state.map { $0 == 3 }
        )
    }

    private func appendApplicationsTypeErrorIfPresent(
        _ plist: [String: Any],
        errors: inout [CollectionError]
    ) {
        if plist.keys.contains("applications") {
            errors.append(CollectionError(
                source: "Firewall",
                message: "ALF preference key 'applications' is not an array; app rules are unknown",
                recoverable: true
            ))
        }
    }
}
