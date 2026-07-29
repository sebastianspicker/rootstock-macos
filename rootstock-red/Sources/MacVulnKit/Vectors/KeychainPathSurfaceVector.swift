import Foundation
import RootstockCore

/// Path-to-impact: keychain database path presence (login / system / metadata).
///
/// Research basis: PEASS keychain path checks; public macOS credential-store recon themes.
/// Safety and behavior: existence metadata only - never reads keychain contents or runs
/// `security dump-keychain`. OPSEC honesty: assess never dumps secrets.
public struct KeychainPathSurfaceVector: Check {
    public static let id = "rootstock.vector.auth.keychain_path_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws
        -> [Finding]
    {
        let paths = Self.keychainPaths(for: state)
        let forced = state.collectorNotes["auth.keychain_paths"] != nil
        guard !paths.present.isEmpty || forced else { return [] }
        return [Self.finding(for: state, paths: paths, forced: forced)]
    }

    private typealias KeychainPath = (kind: String, path: String)

    private static func keychainPaths(for state: CollectedState) -> (
        present: [KeychainPath], forced: [String]
    ) {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path
        let candidates: [KeychainPath] = [
            ("login_keychain_db", "\(home)/Library/Keychains/login.keychain-db"),
            ("login_keychain_legacy", "\(home)/Library/Keychains/login.keychain"),
            ("metadata_keychain_db", "\(home)/Library/Keychains/metadata.keychain-db"),
            ("system_keychain", "/Library/Keychains/System.keychain"),
            ("filevault_master", "/Library/Keychains/FileVaultMaster.keychain"),
            ("user_keychains_dir", "\(home)/Library/Keychains"),
            ("system_keychains_dir", "/Library/Keychains"),
        ]
        var present: [KeychainPath] = []
        for item in candidates where fm.fileExists(atPath: item.path) {
            present.append(item)
        }
        var forcedPaths: [String] = []
        if let note = state.collectorNotes["auth.keychain_paths"] {
            for part in note.split(separator: "|") {
                let p = String(part).trimmingCharacters(in: .whitespaces)
                guard !p.isEmpty else { continue }
                forcedPaths.append(p)
                if !present.contains(where: { $0.path == p }) {
                    present.append((kind: "collector_note", path: p))
                }
            }
        }
        return (present, forcedPaths)
    }

    private static func finding(
        for state: CollectedState,
        paths: (present: [KeychainPath], forced: [String]),
        forced: Bool
    ) -> Finding {
        let dbHits = databasePaths(in: paths.present)
        let credCompound = state.credPaths.contains(where: \.exists)
        let presentation = Self.presentation(dbHits: dbHits, credCompound: credCompound)
        return Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .auth, resolution: .init(evidence: evidence(
                paths: paths, databasePaths: dbHits, forced: forced, credCompound: credCompound), attackTechniques: ["T1555.001", "T1555", "T1003"], remediation: [
                "Protect user sessions; require device unlock for keychain access where policy allows",
                "Prefer hardware-backed credentials / SSO over long-lived keychain secrets when possible",
                "Monitor anomalous security(1) dump / find-generic-password process trees via EDR",
                "OPSEC: assess never dumps secrets - path presence only; do not run dump-keychain in RT assess",
            ], falsePositiveNotes: "login.keychain-db and System.keychain exist on nearly every Mac. Finding is "
                + "path-to-impact ranking for authorized RT, not proof of compromise."), runtime: .init(confidence: dbHits.isEmpty ? .low : .medium, dryRunSafe: true, opsecScore: 14, esfExpected: ["OPEN"]))
    }

    private static func databasePaths(in paths: [KeychainPath]) -> [KeychainPath] {
        paths.filter {
            $0.path.hasSuffix(".keychain-db") || $0.path.hasSuffix(".keychain")
                || $0.kind == "collector_note"
        }
    }

    private static func evidence(
        paths: (present: [KeychainPath], forced: [String]),
        databasePaths: [KeychainPath],
        forced: Bool,
        credCompound: Bool
    ) -> [Evidence] {
        var evidence = [
            Evidence(
                type: "summary",
                detail:
                    "keychainPathsPresent=\(paths.present.count) dbLike=\(databasePaths.count) forced=\(forced) "
                    + "(path presence only - no secret material, no dump-keychain)")
        ]
        evidence += paths.present.prefix(20).map {
            Evidence(
                type: "keychain_path", path: $0.path,
                detail: "kind=\($0.kind) exists=true (metadata only)")
        }
        if !paths.forced.isEmpty {
            evidence.append(
                Evidence(
                    type: "collector_note",
                    detail: "auth.keychain_paths=\(paths.forced.prefix(10).joined(separator: "|"))")
            )
        }
        evidence.append(
            Evidence(
                type: "opsec_honesty",
                detail: "Rootstock Red assess never dumps keychain secrets, never runs "
                    + "`security dump-keychain` / find-generic-password extraction in this vector"))
        if credCompound {
            evidence.append(
                Evidence(
                    type: "auth_compound",
                    detail:
                        "cred path surface also present - keychain + file-cred dual store (still metadata-only)"
                ))
        }
        return evidence
    }

    private static func presentation(dbHits: [KeychainPath], credCompound: Bool) -> (
        severity: Severity, title: String
    ) {
        if !dbHits.isEmpty && credCompound {
            return (
                .medium, "Keychain path surface: DB files + credential-path pivot (\(dbHits.count))"
            )
        }
        if !dbHits.isEmpty {
            return (
                .low,
                "Keychain path surface: login/system keychain DB paths present (\(dbHits.count))"
            )
        }
        return (.low, "Keychain directory surface present (path inventory only)")
    }
}
