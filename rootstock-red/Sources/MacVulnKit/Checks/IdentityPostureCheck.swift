import Foundation
import RootstockCore

/// Emits identity posture findings from AD / Platform SSO filesystem probes.
public struct IdentityPostureCheck: Check {
    public static let id = "rootstock.check.identity.posture"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let identity = state.identity else { return [] }

        var evidence: [Evidence] = []
        evidence.append(
            Evidence(
                type: "identity",
                detail:
                    "adBound=\(identity.adBound.rootstockDescribe) "
                    + "platformSSO=\(identity.platformSSO.rootstockDescribe) "
                    + "kerberosConfigPresent=\(identity.kerberosConfigPresent.rootstockDescribe)"
            )
        )
        for path in identity.odConfigPaths.prefix(20) {
            evidence.append(Evidence(type: "od_path", path: path, detail: "OD/DirectoryService path present"))
        }
        for path in identity.ssoPaths.prefix(20) {
            evidence.append(Evidence(type: "sso_path", path: path, detail: "Platform SSO / AppSSO path present"))
        }
        for note in identity.notes.prefix(25) {
            evidence.append(Evidence(type: "note", detail: note))
        }

        let boundSignals = [
            identity.adBound == true,
            identity.platformSSO == true,
            identity.kerberosConfigPresent == true,
        ].filter { $0 }.count

        let severity: Severity
        let title: String
        if identity.adBound == true || identity.platformSSO == true {
            severity = .info
            var parts: [String] = []
            if identity.adBound == true { parts.append("AD-bound") }
            if identity.platformSSO == true { parts.append("Platform SSO") }
            if identity.kerberosConfigPresent == true { parts.append("Kerberos config") }
            title = "Identity posture: \(parts.joined(separator: ", "))"
        } else if boundSignals == 0 {
            severity = .info
            title = "Identity posture: no AD bind / Platform SSO paths detected"
        } else {
            severity = .info
            title = "Identity posture: partial signals"
        }

        return [
            Finding(id: Self.id, title: title, severity: severity, category: .auth, resolution: .init(evidence: evidence, attackTechniques: ["T1087", "T1082", "T1558"], remediation: [
                    "Informational directory / SSO join state for engagement notes",
                    "Validate AD/Platform SSO via inventory systems (not only local heuristics)",
                ], falsePositiveNotes: "Path presence is not a live bind/auth proof; Kerberos conf may exist without AD join"), runtime: .init(confidence: identity.adBound != nil || identity.platformSSO != nil ? .medium : .low, dryRunSafe: true, opsecScore: 6, esfExpected: [])),
        ]
    }

}
