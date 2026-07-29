import Foundation
import RootstockCore

/// Path-to-impact: AirPlay receiver dual-use residual.
public struct AirplayReceiverSurfaceVector: Check {
    public static let id = "rootstock.vector.network.airplay_receiver_surface"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.airplayReceiverSurface
        let a = s?.airplayDaemonPaths.count ?? 0
        let b = s?.airplayPrefPaths.count ?? 0
        let c = s?.airplayHelperPaths.count ?? 0
        let surface = s?.airplaySurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.airplay_receiver_surface"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "airplay_receiver_surface_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.airplayDaemonPaths + s.airplayPrefPaths + s.airplayHelperPaths, type: "airplay_receiver_surface_path", detail: "AirPlay receiver dual-use path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "airplay_receiver_surface_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never enables AirPlay Receiver or spoofs AirPlay targets."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "AirPlay receiver dual-use with remote amplifier" : "AirPlay receiver dual-use residual", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1040", "T1021", "T1200"], remediation: [
                "Inventory and baseline AirPlay receiver dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never enables AirPlay Receiver or spoofs AirPlay targets",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
