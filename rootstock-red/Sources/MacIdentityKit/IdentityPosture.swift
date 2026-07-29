import Foundation
import RootstockCore

/// Read-only identity posture (AD bind / Platform SSO) via filesystem heuristics.
///
/// No `dscl`, no shell, no osascript. Evidence is path existence/readability only,
/// never secret material from plists.
public struct IdentityPostureCollector: Collector {
    public static let id = "collect.identity"
    public static let cost: CollectorCost = .low

    public init() {}

    private struct OpenDirectorySignals {
        let paths: [String]
        let adBound: Bool?
    }

    private struct PlatformSSOSignals {
        let paths: [String]
        let present: Bool?
    }

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Identity posture via filesystem heuristics (no dscl/osascript)",
        ]
        let openDirectory = Self.openDirectorySignals(fileManager: fm, notes: &notes)
        let kerberosConfigPresent = Self.kerberosConfiguration(fileManager: fm, notes: &notes)
        let platformSSO = Self.platformSSOSignals(fileManager: fm, notes: &notes)
        let odConfigPaths = Array(Set(openDirectory.paths)).sorted()
        let ssoPaths = Array(Set(platformSSO.paths)).sorted()
        notes.append(
            "Platform SSO signal: \(platformSSO.present == true ? "positive" : "negative") "
                + "(\(ssoPaths.count) path(s))"
        )
        notes.append(
            "Summary: adBound=\(openDirectory.adBound.rootstockDescribe) platformSSO=\(platformSSO.present.rootstockDescribe) "
                + "kerberos=\(kerberosConfigPresent) odPaths=\(odConfigPaths.count) ssoPaths=\(ssoPaths.count)"
        )

        var state = CollectedState()
        state.identity = IdentityState(
            adBound: openDirectory.adBound,
            platformSSO: platformSSO.present,
            kerberosConfigPresent: kerberosConfigPresent,
            odConfigPaths: Array(Set(odConfigPaths)).sorted(),
            ssoPaths: Array(Set(ssoPaths)).sorted(),
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "identity fs probes adBound=\(openDirectory.adBound.rootstockDescribe) "
            + "platformSSO=\(platformSSO.present.rootstockDescribe) kerberos=\(kerberosConfigPresent)"
        return state
    }

    private static func openDirectorySignals(
        fileManager: FileManager,
        notes: inout [String]
    ) -> OpenDirectorySignals {
        let root = "/Library/Preferences/OpenDirectory/Configurations"
        let candidates = [
            "\(root)/Active Directory",
            "/Library/Preferences/DirectoryService/ActiveDirectory.plist",
            "/Library/Preferences/DirectoryService/ActiveDirectoryContact.plist",
            "\(root)/Active Directory/Active Directory.plist",
        ]
        var paths = recordADCandidates(candidates, fileManager: fileManager, notes: &notes)
        let entries = recordConfigurationRoot(root, paths: &paths, fileManager: fileManager, notes: &notes)
        recordDirectoryServicePreferences(paths: &paths, fileManager: fileManager, notes: &notes)
        let bound = adBinding(
            candidates: candidates,
            entries: entries,
            root: root,
            fileManager: fileManager,
            notes: &notes
        )
        return OpenDirectorySignals(paths: paths, adBound: bound)
    }

    private static func recordADCandidates(
        _ candidates: [String],
        fileManager: FileManager,
        notes: inout [String]
    ) -> [String] {
        var paths: [String] = []
        for path in candidates {
            let exists = fileManager.fileExists(atPath: path)
            if exists {
                paths.append(path)
                notes.append("AD candidate: \(path) exists=\(exists) readable=\(fileManager.isReadableFile(atPath: path))")
            } else {
                notes.append("AD candidate: \(path) missing")
            }
        }
        return paths
    }

    private static func recordConfigurationRoot(
        _ root: String,
        paths: inout [String],
        fileManager: FileManager,
        notes: inout [String]
    ) -> [String] {
        guard fileManager.fileExists(atPath: root) else {
            notes.append("OD Configurations root missing: \(root)")
            return []
        }
        paths.append(root)
        guard let entries = try? fileManager.contentsOfDirectory(atPath: root) else {
            notes.append("OD Configurations present but not listable (permissions)")
            return []
        }
        let sortedEntries = entries.sorted()
        notes.append("OD Configurations listable (\(sortedEntries.count)): \(sortedEntries.joined(separator: ", "))")
        for name in sortedEntries {
            let path = (root as NSString).appendingPathComponent(name)
            if !paths.contains(path) { paths.append(path) }
        }
        return sortedEntries
    }

    private static func recordDirectoryServicePreferences(
        paths: inout [String],
        fileManager: FileManager,
        notes: inout [String]
    ) {
        let preferences = [
            "/Library/Preferences/DirectoryService/DirectoryService.plist",
            "/Library/Preferences/DirectoryService/SearchNodeConfig.plist",
            "/Library/Preferences/com.apple.DirectoryService.plist",
        ]
        for path in preferences {
            let exists = fileManager.fileExists(atPath: path)
            notes.append("DirectoryService prefs: \(path) exists=\(exists)")
            if exists { paths.append(path) }
        }
    }

    private static func adBinding(
        candidates: [String],
        entries: [String],
        root: String,
        fileManager: FileManager,
        notes: inout [String]
    ) -> Bool? {
        let pathHit = candidates.contains { fileManager.fileExists(atPath: $0) }
        let nameHit = entries.contains {
            $0.localizedCaseInsensitiveContains("Active Directory")
                || $0.localizedCaseInsensitiveContains("ActiveDirectory")
                || $0.caseInsensitiveCompare("AD") == .orderedSame
        }
        if pathHit || nameHit {
            notes.append("AD bind signal: positive (path and/or OD node name)")
            return true
        }
        if fileManager.fileExists(atPath: root), (try? fileManager.contentsOfDirectory(atPath: root)) != nil {
            notes.append("AD bind signal: negative (OD configs readable, no AD node/path)")
            return false
        }
        notes.append("AD bind signal: unknown (insufficient OD path visibility)")
        return nil
    }

    private static func kerberosConfiguration(fileManager: FileManager, notes: inout [String]) -> Bool {
        let paths = [
            "/Library/Preferences/edu.mit.Kerberos", "/etc/krb5.conf", "/private/etc/krb5.conf",
            (NSHomeDirectory() as NSString).appendingPathComponent("Library/Preferences/edu.mit.Kerberos"),
        ]
        let hits = paths.filter { fileManager.fileExists(atPath: $0) }
        for path in paths {
            notes.append("Kerberos: \(path) exists=\(fileManager.fileExists(atPath: path))")
        }
        if !hits.isEmpty {
            notes.append("Kerberos config present at: \(hits.joined(separator: ", "))")
        }
        return !hits.isEmpty
    }

    private static func platformSSOSignals(
        fileManager: FileManager,
        notes: inout [String]
    ) -> PlatformSSOSignals {
        let home = NSHomeDirectory()
        var paths = existingPaths(
            [
                "/Library/Application Support/com.apple.PlatformSSO",
                (home as NSString).appendingPathComponent("Library/Application Support/com.apple.PlatformSSO"),
            ],
            prefix: "PlatformSSO support dir",
            fileManager: fileManager,
            notes: &notes
        )
        paths += existingPaths(
            [
                "/Library/Preferences/com.apple.PlatformSSO.plist",
                "/Library/Managed Preferences/com.apple.PlatformSSO.plist",
                "/Library/Managed Preferences/com.apple.AppSSO.plist",
                "/Library/Preferences/com.apple.AppSSO.plist",
                "/Library/Managed Preferences/com.apple.AppSSOAgent.plist",
            ],
            prefix: "SSO prefs",
            fileManager: fileManager,
            notes: &notes
        )
        paths += ssoDirectoryPaths(
            directory: "/Library/Application Support",
            prefix: "SSO-related Application Support",
            fileManager: fileManager,
            matches: applicationSupportSSOName,
            notes: &notes
        )
        paths += ssoDirectoryPaths(
            directory: "/Library/Managed Preferences",
            prefix: "SSO managed preference",
            fileManager: fileManager,
            matches: managedPreferenceSSOName,
            notes: &notes
        )
        return PlatformSSOSignals(paths: paths, present: paths.isEmpty ? false : true)
    }

    private static func existingPaths(
        _ candidates: [String],
        prefix: String,
        fileManager: FileManager,
        notes: inout [String]
    ) -> [String] {
        for path in candidates {
            notes.append("\(prefix): \(path) exists=\(fileManager.fileExists(atPath: path))")
        }
        return candidates.filter { fileManager.fileExists(atPath: $0) }
    }

    private static func ssoDirectoryPaths(
        directory: String,
        prefix: String,
        fileManager: FileManager,
        matches: (String) -> Bool,
        notes: inout [String]
    ) -> [String] {
        guard let entries = try? fileManager.contentsOfDirectory(atPath: directory) else { return [] }
        let paths = entries.filter(matches).sorted().map { (directory as NSString).appendingPathComponent($0) }
        for path in paths { notes.append("\(prefix): \(path)") }
        return paths
    }

    private static func applicationSupportSSOName(_ name: String) -> Bool {
        let lower = name.lowercased()
        return ["platformsso", "appssso", "app.sso", "com.apple.appsso", "ssoextension", "sso-extension"].contains {
            lower.contains($0)
        }
    }

    private static func managedPreferenceSSOName(_ name: String) -> Bool {
        let lower = name.lowercased()
        return ["platformsso", "appssso", "appsso", "sso"].contains { lower.contains($0) }
    }

}
