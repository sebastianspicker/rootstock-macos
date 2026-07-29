import Foundation
import RootstockCore

/// User-writable configuration profile / mobileconfig sideload risk (path only).
///
/// Research basis: MDM / profile sideload tradecraft; user Downloads as profile drop path;
/// ConfigurationProfiles store inventory ideas.
/// Safety and behavior: typed `ConfigProfileSideloadState`; lists paths/counts only - never
/// installs profiles, never parses payload secrets, never dumps profile DB contents.
///
/// Honesty: prefs names like `com.apple.SystemProfiler.plist` contain the substring
/// "profile" but are not configuration-profile sideload surface. Matching is tight.
public struct ConfigProfileSideloadCollector: Collector {
    public static let id = "collect.config_profile_sideload"
    public static let cost: CollectorCost = .low

    private static let profileInstallDbCandidates: [String] = [
        "/var/db/ConfigurationProfiles",
        "/private/var/db/ConfigurationProfiles",
        "/Library/ConfigurationProfiles",
        "/var/db/ConfigurationProfiles/Store",
    ]

    /// Prefs basenames that look like config-profile / MDM surface (not SystemProfiler).
    public static func isConfigurationProfilePrefName(_ name: String) -> Bool {
        let lower = name.lowercased()
        let exclusions = ["systemprofiler", "system_profiler", "activitymonitor"]
        guard !exclusions.contains(where: lower.contains) else { return false }

        let directSignals = ["mobileconfig", "configurationprofile", "configurationprofiles", "pppc", "tcc.configuration"]
        if lower.hasSuffix(".mobileconfig")
            || lower.hasPrefix("com.apple.managedclient")
            || directSignals.contains(where: lower.contains)
        {
            return true
        }

        let mdmContext = lower.contains("mdm")
            && ["profile", "enroll"].contains(where: lower.contains)
        let contextualProfile = [["config", "profile"], ["enroll", "profile"]]
            .contains { fragments in fragments.allSatisfy(lower.contains) }
        return mdmContext || contextualProfile
    }

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fileManager = FileManager.default
        let home = NSHomeDirectory()
        var notes: [String] = [
            "Config profile sideload surface: path/count only - no install, no payload parse",
            "Prefs filter excludes SystemProfiler and other non-config-profile names",
        ]

        let mobileconfigs = Self.discoverMobileconfigs(
            fileManager: fileManager,
            home: home,
            notes: &notes
        )
        var userPaths = mobileconfigs.paths
        var profileHints = mobileconfigs.downloadHints
        profileHints += Self.preferenceHints(fileManager: fileManager, home: home, notes: &notes)
        let profileStorePresent = Self.profileStorePresent(fileManager: fileManager, notes: &notes)

        userPaths = Self.capped(userPaths, named: "userMobileconfigPaths", notes: &notes)
        profileHints = Self.capped(profileHints, named: "downloadsProfileHints", notes: &notes)
        userPaths = Array(Set(userPaths)).sorted()
        profileHints = Array(Set(profileHints)).sorted()

        var state = CollectedState()
        state.configProfileSideload = ConfigProfileSideloadState(
            userMobileconfigPaths: userPaths,
            downloadsProfileHints: profileHints,
            profileInstallDbPresent: profileStorePresent,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "mobileconfigs=\(userPaths.count) hints=\(profileHints.count) "
            + "profileDb=\(profileStorePresent.map(String.init(describing:)) ?? "nil")"
        return state
    }

    private static func discoverMobileconfigs(
        fileManager: FileManager,
        home: String,
        notes: inout [String]
    ) -> (paths: [String], downloadHints: [String]) {
        let downloads = (home as NSString).appendingPathComponent("Downloads")
        var paths: [String] = []
        var downloadHints: [String] = []

        switch (fileManager.fileExists(atPath: downloads), try? fileManager.contentsOfDirectory(atPath: downloads)) {
        case (true, let items?):
            let names = items.filter { $0.lowercased().hasSuffix(".mobileconfig") }
            let found = names.map { (downloads as NSString).appendingPathComponent($0) }
            paths += found
            downloadHints += found
            notes.append("Downloads mobileconfig count=\(found.count) dir=\(downloads)")
        case (true, nil):
            notes.append("Downloads present but listing denied: \(downloads)")
        case (false, _):
            notes.append("Downloads directory absent: \(downloads)")
        }

        for directory in ["Desktop", "Documents"].map({ (home as NSString).appendingPathComponent($0) }) {
            guard
                fileManager.fileExists(atPath: directory),
                let items = try? fileManager.contentsOfDirectory(atPath: directory)
            else { continue }

            for name in items where name.lowercased().hasSuffix(".mobileconfig") {
                let path = (directory as NSString).appendingPathComponent(name)
                paths.append(path)
                notes.append("user_mobileconfig: \(path)")
            }
        }
        return (paths, downloadHints)
    }

    private static func preferenceHints(
        fileManager: FileManager,
        home: String,
        notes: inout [String]
    ) -> [String] {
        let directory = (home as NSString).appendingPathComponent("Library/Preferences")
        guard let items = try? fileManager.contentsOfDirectory(atPath: directory) else {
            notes.append("User Preferences dir unreadable or absent")
            return []
        }

        let profileHints = items.filter(isConfigurationProfilePrefName)
        for name in profileHints {
            notes.append("user_prefs_config_profile_hint: \(name)")
        }
        if items.contains(where: { $0.lowercased().contains("systemprofiler") }) {
            notes.append("excluded_prefs_false_friend: SystemProfiler (not configuration profile)")
        }
        return profileHints.map { "prefs:\((directory as NSString).appendingPathComponent($0))" }
    }

    private static func profileStorePresent(fileManager: FileManager, notes: inout [String]) -> Bool? {
        let paths = profileInstallDbCandidates.filter(fileManager.fileExists(atPath:))
        if paths.isEmpty {
            notes.append("ConfigurationProfiles store not observed at catalog paths")
            return false
        }
        for path in paths {
            notes.append("profile_store present: \(path) (not dumping contents)")
        }
        return true
    }

    private static func capped(_ paths: [String], named name: String, notes: inout [String]) -> [String] {
        let maxPaths = 50
        guard paths.count > maxPaths else { return paths }
        notes.append("\(name) truncated \(paths.count)→\(maxPaths)")
        return Array(paths.prefix(maxPaths))
    }
}
