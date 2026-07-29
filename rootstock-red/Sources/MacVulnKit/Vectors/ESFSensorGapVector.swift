import Foundation
import RootstockCore

/// Path-to-impact: Endpoint Security / EDR sensor gap vs remote or high-value surface.
///
/// Research basis: ESF talks; Atomic purple pairs; security product path catalogs.
/// Safety and behavior: typed ESF posture compound with remote/identity; never auto-disables sensors.
public struct ESFSensorGapVector: Check {
    public static let id = "rootstock.vector.esf.sensor_gap"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard shouldReport(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func shouldReport(_ state: CollectedState) -> Bool {
        let esf = state.esf
        let productPresent = state.securityProducts.contains(where: \.present)
        // clientPaths = third-party EDR/ES clients only (Apple infra excluded by collector).
        let thirdPartyClientCount = esf?.clientPaths.count ?? 0
        let hints = esf?.edrHints ?? []
        let thirdPartySysext = esf?.systemExtensionCount ?? 0

        // Thin third-party sensor: no product catalog hits, no third-party clients/hints.
        // Stock Apple ES infrastructure (endpointsecurityd / framework) must NOT suppress this.
        let thinThirdPartySensor =
            !productPresent
            && thirdPartyClientCount == 0
            && hints.isEmpty

        return thinThirdPartySensor && (Self.hasRemoteAccess(state) || Self.hasHighValueSurface(state) || Self.hasGapNote(state))
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let esf = state.esf
        let thirdPartyClientCount = esf?.clientPaths.count ?? 0
        let hints = esf?.edrHints ?? []
        let thirdPartySysext = esf?.systemExtensionCount ?? 0
        let remote = Self.hasRemoteAccess(state)
        let highValue = Self.hasHighValueSurface(state)
        var evidence = Self.baseEvidence(ESFBaseEvidenceInput(state: state, notes: esf?.notes ?? [], paths: esf?.clientPaths ?? [], clientCount: thirdPartyClientCount, hints: hints, systemExtensions: thirdPartySysext))
        if remote {
            evidence.append(
                Evidence(
                    type: "compound_remote",
                    detail:
                        "ssh=\((state.network?.remoteLoginSSH).rootstockDescribe) "
                        + "ard=\((state.network?.screenSharingARD).rootstockDescribe)"
                )
            )
        }
        if highValue {
            evidence.append(
                Evidence(
                    type: "compound_high_value",
                    detail:
                        "credPaths=\(state.credPaths.filter(\.exists).count) "
                        + "platformSSO=\((state.identity?.platformSSO).rootstockDescribe) "
                        + "adBound=\((state.identity?.adBound).rootstockDescribe)"
                )
            )
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Path probes miss many commercial agents (MDM-deployed sysexts). "
                    + "Treat as posture gap candidate, not proof of disabled EDR."
            )
        )

        return evidence
    }

    private static func baseEvidence(_ input: ESFBaseEvidenceInput) -> [Evidence] {
        var evidence = [Evidence(type: "sensor_summary", detail: "securityProductsPresent=\(input.state.securityProducts.filter(\.present).count) " + "thirdPartyClients=\(input.clientCount) edrHints=\(input.hints.count) " + "thirdPartySysext≈\(input.systemExtensions) " + "(Apple ES infrastructure excluded from client count)")]
        evidence += input.notes.prefix(12).map { Evidence(type: "esf_note", detail: $0) }
        evidence += input.paths.prefix(12).map { Evidence(type: "third_party_client", path: $0, detail: "third-party ES/EDR path") }
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let remote = hasRemoteAccess(state)
        let thinThirdPartySensor = !state.securityProducts.contains(where: \.present)
            && (state.esf?.clientPaths.count ?? 0) == 0 && (state.esf?.edrHints ?? []).isEmpty
        let severity: Severity = (thinThirdPartySensor && remote) ? .medium : .low
        return Finding(id: Self.id, title: thinThirdPartySensor && remote
                    ? "ESF/EDR sensor gap: no third-party sensor inventory with remote access enabled"
                    : "ESF/EDR sensor posture: thin third-party Endpoint Security coverage", severity: severity, category: .securityProduct, resolution: .init(evidence: evidence, attackTechniques: ["T1518.001", "T1562.001", "T1021"], remediation: [
                    "Confirm EDR/ES client deployment via MDM inventory (not only local paths)",
                    "Prioritize sensor coverage on hosts with Remote Login / Screen Sharing",
                    "Purple: pair assess findings with ESF OPEN/EXEC expectations for dual-use bins",
                    "OPSEC: Rootstock Red never unloads ES clients or disables security products",
                ], falsePositiveNotes: "Many enterprise agents install under vendor-specific paths not in the probe catalog. "
                    + "Absence of path hits ≠ confirmed absence of telemetry."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 12, esfExpected: ["OPEN"]))
    }

    private static func hasRemoteAccess(_ state: CollectedState) -> Bool { state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true }
    private static func hasHighValueSurface(_ state: CollectedState) -> Bool { state.credPaths.contains(where: \.exists) || state.identity?.platformSSO == true || state.identity?.adBound == true }
    private static func hasGapNote(_ state: CollectedState) -> Bool { state.collectorNotes["esf.sensor_gap"] != nil || state.collectorNotes["collect.esf_endpoint_security"]?.contains("thirdPartyClients=0") == true }

}

private struct ESFBaseEvidenceInput {
    let state: CollectedState
    let notes: [String]
    let paths: [String]
    let clientCount: Int
    let hints: [String]
    let systemExtensions: Int
}
