import Foundation
import RootstockCore

/// Path-to-impact: Spotlight importer residual depth.
public struct SpotlightImporterDepthVector: Check {
    public static let id = "rootstock.vector.data.spotlight_importer_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.spotlightImporterDepth
        let a = s?.metadataToolPaths.count ?? 0
        let b = s?.spotlightImporterPaths.count ?? 0
        let c = s?.mdsLaunchPaths.count ?? 0
        let surface = s?.spotlightImporterSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.spotlight_importer_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "spotlight_importer_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.metadataToolPaths + s.spotlightImporterPaths + s.mdsLaunchPaths, type: "spotlight_importer_depth_path", detail: "Spotlight importer depth path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "spotlight_importer_depth_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs malicious Spotlight importers or dumps mdworker index contents."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Spotlight importer depth with remote amplifier" : "Spotlight importer residual depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1083", "T1005", "T1213"], remediation: [
                "Inventory and baseline Spotlight importer depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs malicious Spotlight importers or dumps mdworker index contents",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
