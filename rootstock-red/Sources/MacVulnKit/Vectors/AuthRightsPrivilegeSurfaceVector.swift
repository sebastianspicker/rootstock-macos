import Foundation
import RootstockCore

/// Path-to-impact: authorization database / PackageKit privilege surface.
///
/// Research basis: auth.db / authd / PackageKit privilege literature; PEASS auth themes.
/// Safety and behavior: typed AuthRightsState compound findings; never dumps rights or auth.db rows.
public struct AuthRightsPrivilegeSurfaceVector: Check {
    public static let id = "rootstock.vector.auth.rights_privilege_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let auth = eligibleAuth(in: state) else {
            return state.collectorNotes["collect.auth_rights"] == nil ? [] : [Self.findingFromNotes(state: state)]
        }
        let sipOff = state.protections?.sipEnabled == false
        let nonRoot = state.host?.isRoot == false
        return [Self.finding(
            auth: auth,
            evidence: evidence(for: auth, sipOff: sipOff, nonRoot: nonRoot),
            severity: sipOff && auth.authDbPresent == true ? .medium : .low,
            sipOff: sipOff
        )]
    }

private func eligibleAuth(in state: CollectedState) -> AuthRightsState? {
        guard let auth = state.authRights else { return nil }
        let present = auth.authDbPresent == true
            || !auth.authorizationPlistPaths.isEmpty
            || !auth.packageKitPaths.isEmpty
            || auth.rightsHintCount > 0
        return present ? auth : nil
    }

    private func evidence(for auth: AuthRightsState, sipOff: Bool, nonRoot: Bool) -> [Evidence] {
        var evidence = [Evidence(
            type: "auth_summary",
            detail: "authDbPresent=\(auth.authDbPresent.rootstockDescribe) authDbPath=\(auth.authDbPath ?? "nil") authorizationPlists=\(auth.authorizationPlistPaths.count) packageKit=\(auth.packageKitPaths.count) rightsHints=\(auth.rightsHintCount)"
        )]
        if let path = auth.authDbPath {
            evidence.append(Evidence(type: "auth_db", path: path, detail: "auth.db path presence only"))
        }
        for path in (auth.authorizationPlistPaths + auth.packageKitPaths).prefix(10) {
            evidence.append(Evidence(type: "auth_path", path: path, detail: "privilege-adjacent path"))
        }
        for note in auth.notes.prefix(8) {
            evidence.append(Evidence(type: "auth_note", detail: note))
        }
        if sipOff { evidence.append(Evidence(type: "compound_sip", detail: "sipEnabled=false")) }
        if nonRoot { evidence.append(Evidence(type: "compound_priv", detail: "assess running as non-root")) }
        evidence.append(Evidence(
            type: "honesty",
            detail: "Presence of auth.db / PackageKit is expected on stock macOS. Finding flags the privilege surface for authorized review - not a confirmed misconfiguration."
        ))
        return evidence
    }

    private static func finding(
        auth: AuthRightsState,
        evidence: [Evidence],
        severity: Severity,
        sipOff: Bool
    ) -> Finding {
        Finding(id: Self.id, title: sipOff
                ? "Auth rights / PackageKit privilege surface with SIP reported disabled"
                : "Authorization rights / PackageKit privilege surface present", severity: severity, category: .auth, resolution: .init(evidence: evidence, attackTechniques: ["T1548", "T1548.004", "T1068"], remediation: [
                "Keep SIP enabled; treat auth.db modifications as high-change-control events",
                "Audit custom authorization rights and installer policies via MDM compliance",
                "Restrict who may run installer / PackageKit workflows on high-value hosts",
                "OPSEC: Rootstock Red never edits auth.db or injects authorization rights",
            ], falsePositiveNotes: "auth.db and PackageKit exist on nearly all macOS installs; severity rises only with compounds (SIP off, custom rights hints)."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 18, esfExpected: ["OPEN", "WRITE"]))
    }

    private static func findingFromNotes(state: CollectedState) -> Finding {
        Finding(id: id, title: "Authorization rights surface (collector note only)", severity: .info, category: .auth, resolution: .init(evidence: [
                Evidence(
                    type: "collector_note",
                    detail: state.collectorNotes["collect.auth_rights"] ?? ""
                ),
            ], attackTechniques: ["T1548"], remediation: ["Re-run assess with auth rights collector for typed state"]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 10, esfExpected: ["OPEN"]))
    }

}
