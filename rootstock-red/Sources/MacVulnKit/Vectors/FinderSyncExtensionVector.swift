import Foundation
import RootstockCore

/// Path-to-impact: Finder Sync extension dual-use surface.
public struct FinderSyncExtensionVector: Check {
    public static let id = "rootstock.vector.persist.finder_sync_extension"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.finderSyncExtension
        let a = s?.finderSyncFrameworkPaths.count ?? 0
        let b = s?.appScriptPaths.count ?? 0
        let c = s?.finderPrefPaths.count ?? 0
        let surface = s?.finderSyncSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.finder_sync_extension"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "finder_sync_extension_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.finderSyncFrameworkPaths + s.appScriptPaths + s.finderPrefPaths, type: "finder_sync_extension_path", detail: "Finder Sync dual-use path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "finder_sync_extension_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs Finder Sync extensions or rewrites Finder preferences for abuse."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Finder Sync dual-use with remote amplifier" : "Finder Sync extension dual-use surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1546", "T1176", "T1059"], remediation: [
                "Inventory and baseline Finder Sync dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs Finder Sync extensions or rewrites Finder preferences for abuse",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
