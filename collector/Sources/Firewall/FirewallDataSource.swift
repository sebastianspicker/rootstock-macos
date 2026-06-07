import Foundation
import Models

/// Collects macOS Application Firewall (ALF) status and per-app rules.
///
/// Reads from `/Library/Preferences/com.apple.alf.plist` which is readable
/// without elevation. Provides global firewall state and per-application rules.
public struct FirewallDataSource: DataSource {
    public let name = "Firewall"
    public let requiresElevation = false

    private let alfPlistPath: String
    struct ALFParseResult {
        let status: FirewallStatus
        let errors: [CollectionError]
    }

    public init(alfPlistPath: String = "/Library/Preferences/com.apple.alf.plist") {
        self.alfPlistPath = alfPlistPath
    }

    public func collect() async -> DataSourceResult {
        var errors: [CollectionError] = []

        guard let plistData = try? Data(contentsOf: URL(fileURLWithPath: alfPlistPath)),
              let plist = try? PropertyListSerialization.propertyList(
                   from: plistData, format: nil
               ) as? [String: Any] else {
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
