import Foundation
import RootstockCore

/// Path-to-impact: Emond legacy rules residual depth.
public struct EmondLegacyDepthVector: Check {
    public static let id = "rootstock.vector.persist.emond_legacy_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.emondLegacyDepth
        let a = s?.emondBinaryPaths.count ?? 0
        let b = s?.emondRulePaths.count ?? 0
        let c = s?.emondSupportPaths.count ?? 0
        let surface = s?.emondSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.emond_legacy_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "emond_legacy_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.emondBinaryPaths + s.emondRulePaths + s.emondSupportPaths, type: "emond_legacy_depth_path", detail: "Emond legacy depth path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "emond_legacy_depth_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs emond rules or enables the legacy event monitor daemon."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Emond legacy depth with remote amplifier" : "Emond legacy rules residual depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1546.014", "T1546", "T1059"], remediation: [
                "Inventory and baseline Emond legacy depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs emond rules or enables the legacy event monitor daemon",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
