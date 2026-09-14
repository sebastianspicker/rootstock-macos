import Foundation
import RootstockCore

/// Emits identity posture findings from AD / Platform SSO filesystem probes.
public struct IdentityPostureCheck: Check {
    public static let id = "rootstock.check.identity.posture"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let identity = state.identity else { return [] }
        let presentation = Self.presentation(for: identity)

        return [
            Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .auth, resolution: .init(evidence: Self.evidence(for: identity), attackTechniques: ["T1087", "T1082", "T1558"], remediation: [
                    "Informational directory / SSO join state for engagement notes",
                    "Validate AD/Platform SSO via inventory systems (not only local heuristics)",
                ], falsePositiveNotes: "Path presence is not a live bind/auth proof; Kerberos conf may exist without AD join"), runtime: .init(confidence: identity.adBound != nil || identity.platformSSO != nil ? .medium : .low, dryRunSafe: true, opsecScore: 6, esfExpected: [])),
        ]
    }

    private static func evidence(for identity: IdentityState) -> [Evidence] {
        var evidence = [
            Evidence(
                type: "identity",
                detail:
                    "adBound=\(identity.adBound.rootstockDescribe) "
                    + "platformSSO=\(identity.platformSSO.rootstockDescribe) "
                    + "kerberosConfigPresent=\(identity.kerberosConfigPresent.rootstockDescribe)"
            ),
        ]
        evidence += identity.odConfigPaths.prefix(20).map {
            Evidence(type: "od_path", path: $0, detail: "OD/DirectoryService path present")
        }
        evidence += identity.ssoPaths.prefix(20).map {
            Evidence(type: "sso_path", path: $0, detail: "Platform SSO / AppSSO path present")
        }
        evidence += identity.notes.prefix(25).map { Evidence(type: "note", detail: $0) }
        return evidence
    }

    private static func presentation(for identity: IdentityState) -> (title: String, severity: Severity) {
        let isBound = identity.adBound == true || identity.platformSSO == true
        if isBound {
            let labels = [
                identity.adBound == true ? "AD-bound" : nil,
                identity.platformSSO == true ? "Platform SSO" : nil,
                identity.kerberosConfigPresent == true ? "Kerberos config" : nil,
            ].compactMap { $0 }
            return ("Identity posture: \(labels.joined(separator: ", "))", .info)
        }
        let hasSignals = identity.kerberosConfigPresent == true
        return hasSignals
            ? ("Identity posture: partial signals", .info)
            : ("Identity posture: no AD bind / Platform SSO paths detected", .info)
    }
}
