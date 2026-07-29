import Foundation
import RootstockCore

/// SIP / Gatekeeper / FileVault posture from collected protections state.
public struct ProtectionsPostureCheck: Check {
    public static let id = "rootstock.check.protections.posture"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let p = state.protections else { return [] }

        var evidence: [Evidence] = []
        evidence.append(contentsOf: p.notes.map { Evidence(type: "note", detail: $0) })
        evidence.append(
            Evidence(type: "sip", detail: "sipEnabled=\(p.sipEnabled.rootstockDescribe)")
        )
        evidence.append(
            Evidence(type: "gatekeeper", detail: "gatekeeperEnabled=\(p.gatekeeperEnabled.rootstockDescribe)")
        )
        evidence.append(
            Evidence(type: "filevault", detail: "fileVaultOn=\(p.fileVaultOn.rootstockDescribe)")
        )

        let disabled: [(String, Bool?)] = [
            ("SIP", p.sipEnabled),
            ("Gatekeeper", p.gatekeeperEnabled),
            ("FileVault", p.fileVaultOn),
        ]
        let knownDisabled = disabled.filter { $0.1 == false }.map(\.0)
        let allUnknown =
            p.sipEnabled == nil && p.gatekeeperEnabled == nil && p.fileVaultOn == nil

        let severity: Severity
        let title: String
        let confidence: Confidence
        if !knownDisabled.isEmpty {
            severity = .low
            confidence = .medium
            title = "Protections disabled or weak: \(knownDisabled.joined(separator: ", "))"
        } else if allUnknown {
            severity = .info
            confidence = .low
            title = "Protections posture unknown (evidence-only probe)"
        } else {
            severity = .info
            confidence = .medium
            title = "Protections posture snapshot"
        }

        return [
            Finding(id: Self.id, title: title, severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1562.001", "T1082"], remediation: [
                    "Confirm SIP, Gatekeeper, and FileVault via MDM compliance / admin tooling",
                    "Assess mode avoids csrutil/spctl shell storms by default",
                ], falsePositiveNotes: knownDisabled.isEmpty
                    ? "Unknown values are not proof of disabled protections"
                    : "Verify disabled flags with privileged host tooling before remediating"), runtime: .init(confidence: confidence, dryRunSafe: true, opsecScore: 10, esfExpected: [])),
        ]
    }

}
