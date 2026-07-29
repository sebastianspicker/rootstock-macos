import Foundation
import RootstockCore

/// Path-to-impact: Maps / location services residual plane.
public struct MapsLocationPathVector: Check {
    public static let id = "rootstock.vector.data.maps_location_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.mapsLocationPath
        let a = s?.mapsAppPaths.count ?? 0
        let b = s?.mapsCachePaths.count ?? 0
        let c = s?.locationdPaths.count ?? 0
        let surface = s?.mapsLocationSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.maps_location_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "maps_location_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.mapsAppPaths + s.mapsCachePaths + s.locationdPaths, type: "maps_location_path_path", detail: "Maps location residual path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "maps_location_path_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps location history or spoofs CoreLocation positions."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Maps location residual with remote amplifier" : "Maps / location services residual plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1011", "T1083", "T1005"], remediation: [
                "Inventory and baseline Maps location residual paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps location history or spoofs CoreLocation positions",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
