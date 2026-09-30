import Foundation
import RootstockCore

/// Read-only MDM / management posture - vendor paths, managed prefs, profile store.
///
/// Pure filesystem (no `profiles` CLI). Records paths/names only; never parses
/// binary profile secrets or PPPC payload contents.
public struct MdmPostureCollector: Collector {
    public static let id = "collect.mdm"
    public static let cost: CollectorCost = .low

    private static let vendorPaths: [(String, String)] = [
        ("Jamf", "/usr/local/bin/jamf"),
        ("Jamf", "/usr/local/jamf/bin/jamf"),
        ("Kandji", "/Library/Kandji"),
        ("Mosyle", "/Library/Application Support/Mosyle"),
        ("Intune", "/Library/Intune"),
        ("Company Portal", "/Applications/Company Portal.app"),
        ("Workspace ONE", "/Library/Application Support/AirWatch"),
        ("Addigy", "/Library/Addigy"),
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "MDM posture via filesystem heuristics (no profiles CLI)"
        ]
        let vendorHints = Self.vendorHints(fm: fm, notes: &notes)
        let managedPreferences = Self.managedPreferences(fm: fm, notes: &notes)
        let pppcPath = Self.pppcPath(
            managedPreferenceNames: managedPreferences.names,
            root: managedPreferences.root,
            fm: fm,
            notes: &notes
        )
        let pppcPolicyPresent: Bool? = pppcPath != nil
        let profileStores = Self.profileStores(fm: fm, notes: &notes)
        let enrollHits = Self.enrollmentPaths(fm: fm, notes: &notes)
        let enrolled = Self.enrollmentStatus(
            EnrollmentStatusInput(vendorHints: vendorHints, enrollmentPaths: enrollHits, managedPreferenceNames: managedPreferences.names, profileStores: profileStores, pppcPolicyPresent: pppcPolicyPresent == true),
            notes: &notes
        )

        let profileFileCount = profileStores.fileCount.map(String.init) ?? "nil"
        let summary =
            "Summary: enrolled=\(enrolled.rootstockDescribe) vendors=\(vendorHints.joined(separator: ",")) "
            + "managedPrefs=\(managedPreferences.names.count) profileStoreReadable=\(profileStores.readable.rootstockDescribe) "
            + "profileFiles=\(profileFileCount) pppc=\(pppcPolicyPresent.rootstockDescribe)"
        notes.append(summary)

        var state = CollectedState()
        state.mdm = MDMState(
            enrolled: enrolled,
            vendorHints: vendorHints,
            managedPreferenceNames: managedPreferences.names,
            profileStoreReadable: profileStores.readable,
            profileFileCount: profileStores.fileCount,
            pppcPolicyPresent: pppcPolicyPresent,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "mdm fs+vendor enrolled=\(enrolled.rootstockDescribe) "
            + "vendors=\(vendorHints.count) managedPrefs=\(managedPreferences.names.count) "
            + "profiles=\(profileStores.fileCount.map(String.init) ?? "nil")"
        return state
    }

    private struct ManagedPreferences {
        let root: String
        let names: [String]
    }

    private struct ProfileStores {
        let readable: Bool?
        let fileCount: Int?
        let hasStore: Bool
    }

    private struct ProfileStoreRecordInput {
        let path: String
        let readable: Bool
        let fileManager: FileManager
    }

    private struct ProfileStoreRecordState {
        var readable: Bool?
        var fileCount: Int?
    }

    private struct EnrollmentStatusInput {
        let vendorHints: [String]
        let enrollmentPaths: [String]
        let managedPreferenceNames: [String]
        let profileStores: ProfileStores
        let pppcPolicyPresent: Bool
    }

    private static func vendorHints(fm: FileManager, notes: inout [String]) -> [String] {
        let hints = vendorPaths.compactMap { name, path -> String? in
            let exists = fm.fileExists(atPath: path)
            notes.append("Vendor path: \(name) \(path) exists=\(exists)")
            return exists ? name : nil
        }
        return Array(Set(hints)).sorted()
    }

    private static func managedPreferences(fm: FileManager, notes: inout [String])
        -> ManagedPreferences
    {
        let root = "/Library/Managed Preferences"
        guard fm.fileExists(atPath: root) else {
            notes.append("Managed Preferences root missing: \(root)")
            return ManagedPreferences(root: root, names: [])
        }
        guard let names = try? fm.contentsOfDirectory(atPath: root) else {
            notes.append("Managed Preferences present but not listable")
            return ManagedPreferences(root: root, names: [])
        }
        let sortedNames = names.sorted()
        notes.append("Managed Preferences listable (\(sortedNames.count) top-level names)")
        return ManagedPreferences(root: root, names: sortedNames)
    }

    private static func pppcPath(
        managedPreferenceNames: [String],
        root: String,
        fm: FileManager,
        notes: inout [String]
    ) -> String? {
        let candidates = [
            "/Library/Managed Preferences/com.apple.TCC.configuration-profile-policy.plist",
            "/Library/Managed Preferences/com.apple.TCC.configuration-profile-policy",
            "/var/db/ConfigurationProfiles/Settings/com.apple.TCC.configuration-profile-policy.plist",
        ]
        let path = candidates.first { candidate in
            let exists = fm.fileExists(atPath: candidate)
            notes.append("PPPC policy candidate: \(candidate) exists=\(exists)")
            return exists
        }
        guard path == nil else { return path }
        guard let name = managedPreferenceNames.first(where: isPPPCPolicyName) else { return nil }
        let matchedPath = (root as NSString).appendingPathComponent(name)
        notes.append("PPPC policy matched managed prefs name: \(matchedPath)")
        return matchedPath
    }

    private static func profileStores(fm: FileManager, notes: inout [String]) -> ProfileStores {
        let paths = [
            "/var/db/ConfigurationProfiles",
            "/Library/ConfigurationProfiles",
            "/var/db/ConfigurationProfiles/Store",
        ]
        var readable: Bool?
        var fileCount: Int?
        var hasStore = false
        for path in paths {
            let exists = fm.fileExists(atPath: path)
            let pathReadable = fm.isReadableFile(atPath: path)
            notes.append("Profile store: \(path) exists=\(exists) readable=\(pathReadable)")
            guard exists else { continue }
            hasStore = true
            var record = ProfileStoreRecordState(readable: readable, fileCount: fileCount)
            Self.recordProfileStore(ProfileStoreRecordInput(path: path, readable: pathReadable, fileManager: fm), state: &record, notes: &notes)
            readable = record.readable
            fileCount = record.fileCount
        }
        guard hasStore else {
            notes.append("No configuration profile store paths found")
            return ProfileStores(readable: false, fileCount: 0, hasStore: false)
        }
        return ProfileStores(readable: readable, fileCount: fileCount, hasStore: true)
    }

    private static func recordProfileStore(
        _ input: ProfileStoreRecordInput,
        state: inout ProfileStoreRecordState,
        notes: inout [String]
    ) {
        guard let entries = try? input.fileManager.contentsOfDirectory(atPath: input.path) else {
            recordUnreadableProfileStore(
                input.path, readable: input.readable, profileStoreReadable: &state.readable, notes: &notes
            )
            return
        }
        state.readable = true
        let count = max(
            countProfileLikeFiles(root: input.path, fm: input.fileManager, depth: 0, maxDepth: 2),
            entries.filter(isProfileStoreName).count
        )
        state.fileCount = (state.fileCount ?? 0) + count
        notes.append(
            "Profile store listable: \(input.path) topLevel=\(entries.count) profileLike≈\(count)")
    }

    private static func recordUnreadableProfileStore(
        _ path: String,
        readable: Bool,
        profileStoreReadable: inout Bool?,
        notes: inout [String]
    ) {
        guard !readable else {
            profileStoreReadable = profileStoreReadable ?? true
            notes.append("Profile store readable but contentsOfDirectory failed: \(path)")
            return
        }
        profileStoreReadable = profileStoreReadable ?? false
        notes.append("Profile store not listable (likely root/SIP): \(path)")
    }

    private static func enrollmentPaths(fm: FileManager, notes: inout [String]) -> [String] {
        let paths = [
            "/Library/Preferences/com.apple.ManagedClient.enroll.plist",
            "/Library/Preferences/com.apple.ManagedClient.plist",
            "/var/db/ConfigurationProfiles/MDM_ComputerPrefs.plist",
            "/var/db/ConfigurationProfiles/SecureUserPreferences.plist",
            "/Library/Keychains/FileVaultMaster.keychain",
        ]
        return paths.filter { path in
            let exists = fm.fileExists(atPath: path)
            notes.append("Enrollment/ManagedClient: \(path) exists=\(exists)")
            return exists
        }
    }

    private static func enrollmentStatus(
        _ input: EnrollmentStatusInput,
        notes: inout [String]
    ) -> Bool? {
        let vendorHints = input.vendorHints
        let enrollmentPaths = input.enrollmentPaths
        let managedPreferenceNames = input.managedPreferenceNames
        let profileStores = input.profileStores
        let pppcPolicyPresent = input.pppcPolicyPresent
        let strongSignals =
            !vendorHints.isEmpty
            || !enrollmentPaths.isEmpty
            || (profileStores.fileCount ?? 0) > 0
            || pppcPolicyPresent
            || managedPreferenceNames.contains(where: isManagedMDMPreference)
        guard !strongSignals else {
            notes.append("Enrollment signal: positive (vendor/enroll/profile/PPPC)")
            return true
        }
        guard !managedPreferenceNames.isEmpty && profileStores.hasStore else {
            notes.append(
                "Enrollment signal: unknown (no vendor agent / enroll plist / profile files)")
            return nil
        }
        notes.append("Enrollment signal: likely (managed prefs + profile store present)")
        return true
    }

    private static func isPPPCPolicyName(_ name: String) -> Bool {
        name.localizedCaseInsensitiveContains("TCC.configuration-profile-policy")
    }

    private static func isManagedMDMPreference(_ name: String) -> Bool {
        name.hasPrefix("com.apple.mdm") || name.localizedCaseInsensitiveContains("ManagedClient")
    }

    private static func isProfileStoreName(_ name: String) -> Bool {
        let lower = name.lowercased()
        return isProfileFilename(name) || lower == "store"
            || lower.contains("profile")
    }

    private static func isProfileFilename(_ name: String) -> Bool {
        let lower = name.lowercased()
        return lower.hasSuffix(".mobileconfig")
            || lower.hasSuffix(".profile")
            || lower.hasSuffix(".plist")
    }

    /// Bounded recursive count of profile-like filenames (names only).
    private static func countProfileLikeFiles(
        root: String,
        fm: FileManager,
        depth: Int,
        maxDepth: Int
    ) -> Int {
        guard depth <= maxDepth else { return 0 }
        guard let entries = try? fm.contentsOfDirectory(atPath: root) else { return 0 }
        return entries.reduce(0) { count, name in
            count
                + countProfileLikeEntry(
                    name,
                    under: root,
                    fm: fm,
                    depth: depth,
                    maxDepth: maxDepth
                )
        }
    }

    private static func countProfileLikeEntry(
        _ name: String,
        under root: String,
        fm: FileManager,
        depth: Int,
        maxDepth: Int
    ) -> Int {
        let path = (root as NSString).appendingPathComponent(name)
        var isDirectory: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDirectory) else { return 0 }
        guard isDirectory.boolValue else { return isProfileFilename(name) ? 1 : 0 }
        return countProfileLikeFiles(root: path, fm: fm, depth: depth + 1, maxDepth: maxDepth)
    }

}
