import Foundation
import RootstockCore

/// Path-to-impact: HomeKit residual path plane.
public struct HomekitPathPlaneVector: Check {
    public static let id = "rootstock.vector.data.homekit_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.homekitPathPlane
        let a = s?.homeAppPaths.count ?? 0
        let b = s?.homeKitStorePaths.count ?? 0
        let c = s?.homedPaths.count ?? 0
        let surface = s?.homekitSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.homekit_path_plane"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "homekit_path_plane_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.homeAppPaths + s.homeKitStorePaths + s.homedPaths, type: "homekit_path_plane_path", detail: "HomeKit path plane path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "homekit_path_plane_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never enumerates HomeKit accessory secrets or pairs devices."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "HomeKit path plane with remote amplifier" : "HomeKit residual path plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T0883", "T1005", "T1083"], remediation: [
                "Inventory and baseline HomeKit path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never enumerates HomeKit accessory secrets or pairs devices",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
