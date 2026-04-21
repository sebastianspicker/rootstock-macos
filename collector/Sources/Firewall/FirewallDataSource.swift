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

        let status = parseALFPlist(plist)
        return DataSourceResult(nodes: [status], errors: errors)
    }

    /// Parses the ALF plist dictionary into a FirewallStatus.
    func parseALFPlist(_ plist: [String: Any]) -> FirewallStatus {
        // globalstate: 0=off, 1=on (specific services), 2=essential only
        let globalState = plist["globalstate"] as? Int ?? 0
        let enabled = globalState > 0
        let stealthMode = (plist["stealthenabled"] as? Int ?? 0) != 0
        // allowsignedenabled: automatically allow built-in signed software
        let allowBuiltIn = (plist["allowsignedenabled"] as? Int ?? 0) != 0

        // allowdownloadsignedenabled: automatically allow downloaded signed software
        let allowSigned = (plist["allowdownloadsignedenabled"] as? Int ?? 0) != 0

        // Per-app rules from the "applications" array
        var appRules: [FirewallAppRule] = []
        if let apps = plist["applications"] as? [[String: Any]] {
            for app in apps {
                guard let bundleID = app["bundleid"] as? String else { continue }
                // state: 3 = allow incoming, 4 = block incoming
                let state = app["state"] as? Int ?? 4
                appRules.append(FirewallAppRule(
                    bundleId: bundleID,
                    allowIncoming: state == 3
                ))
            }
        }

        return FirewallStatus(
            enabled: enabled,
            stealthMode: stealthMode,
            allowSigned: allowSigned,
            allowBuiltIn: allowBuiltIn,
            appRules: appRules
        )
    }
}
