import Foundation
import RootstockCore

/// Authorization rights / auth.db / PackageKit privilege surface (path only).
///
/// Research basis: auth.db / authorization.plist research, PackageKit privilege-escalation
/// literature, authd inventory ideas.
/// Safety and behavior: typed `AuthRightsState` for privilege-surface vectors; never dumps
/// auth.db rows or right definitions; path/existence probes only.
public struct AuthRightsCollector: Collector {
    public static let id = "collect.auth_rights"
    public static let cost: CollectorCost = .low

    private static let authDbCandidates: [String] = [
        "/var/db/auth.db",
        "/private/var/db/auth.db",
    ]

    private static let authorizationPlistCandidates: [String] = [
        "/System/Library/Security/authorization.plist",
        "/Library/Security/authorization.plist",
        "/System/Library/Security/Authorization.plist",
    ]

    private static let packageKitCandidates: [String] = [
        "/System/Library/PrivateFrameworks/PackageKit.framework",
        "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/PackageKit",
        "/usr/sbin/installer",
        "/usr/sbin/pkgutil",
        "/System/Library/CoreServices/Installer.app",
    ]

    private static let authdCandidates: [String] = [
        "/usr/libexec/authd",
        "/System/Library/LaunchDaemons/com.apple.authd.plist",
    ]

    /// Additional privilege-surface path probes (presence only; PHT is a sibling collector).
    private static let rightsHintCandidates: [String] = [
        "/usr/libexec/security_authtrampoline",
        "/System/Library/PrivateFrameworks/SystemAdministration.framework",
        "/etc/authorization",
        "/private/etc/authorization",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Auth rights / PackageKit surface: path presence only - no auth.db dump, no right enumeration",
        ]

        let authDbPath = Self.authDbCandidates.first(where: fm.fileExists(atPath:))
        let authDbPresent: Bool? = authDbPath != nil
        notes.append(
            authDbPath.map { "auth.db present: \($0) (not reading rows)" }
                ?? "auth.db not observed at catalog paths (may be SIP/root restricted)"
        )

        let authorizationPlistPaths = Self.existingPaths(
            Self.authorizationPlistCandidates,
            fileManager: fm,
            notePrefix: "authorization.plist",
            notes: &notes
        )
        let packageKitPaths = Self.existingPaths(
            Self.packageKitCandidates,
            fileManager: fm,
            notePrefix: "packagekit",
            notes: &notes
        )
        let authdPaths = Self.existingPaths(Self.authdCandidates, fileManager: fm, notePrefix: "authd", notes: &notes)
        let rightsHintPaths = Self.existingPaths(
            Self.rightsHintCandidates,
            fileManager: fm,
            notePrefix: "rights_hint",
            notes: &notes
        )
        // Count authorization plists as rights-surface hints too.
        let rightsHintCount = authdPaths.count + rightsHintPaths.count + authorizationPlistPaths.count

        var state = CollectedState()
        state.authRights = AuthRightsState(
            authDbPresent: authDbPresent,
            authDbPath: authDbPath,
            authorizationPlistPaths: authorizationPlistPaths,
            packageKitPaths: packageKitPaths,
            rightsHintCount: rightsHintCount,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "authDb=\(authDbPresent.map(String.init(describing:)) ?? "nil") "
            + "authPlists=\(authorizationPlistPaths.count) "
            + "packageKit=\(packageKitPaths.count) "
            + "rightsHints=\(rightsHintCount)"
        return state
    }

    private static func existingPaths(
        _ candidates: [String],
        fileManager: FileManager,
        notePrefix: String,
        notes: inout [String]
    ) -> [String] {
        let paths = candidates.filter(fileManager.fileExists(atPath:))
        for path in paths {
            notes.append("\(notePrefix): \(path)")
        }
        return Array(Set(paths)).sorted()
    }
}
