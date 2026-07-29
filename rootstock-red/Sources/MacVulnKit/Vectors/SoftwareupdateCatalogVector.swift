import Foundation
import RootstockCore

/// Path-to-impact: Software Update catalog residual surface.
public struct SoftwareupdateCatalogVector: Check {
    public static let id = "rootstock.vector.persist.softwareupdate_catalog"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.softwareupdateCatalog
        let a = s?.softwareUpdateToolPaths.count ?? 0
        let b = s?.softwareUpdatePrefPaths.count ?? 0
        let c = s?.softwareUpdateDaemonPaths.count ?? 0
        let surface = s?.softwareUpdateSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.softwareupdate_catalog"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "softwareupdate_catalog_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.softwareUpdateToolPaths + s.softwareUpdatePrefPaths + s.softwareUpdateDaemonPaths, type: "softwareupdate_catalog_path", detail: "Software Update catalog path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "softwareupdate_catalog_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never points SUS catalogs at attacker mirrors or tampers with update plists."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Software Update catalog with remote amplifier" : "Software Update catalog residual surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1072", "T1195", "T1553"], remediation: [
                "Inventory and baseline Software Update catalog paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never points SUS catalogs at attacker mirrors or tampers with update plists",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
