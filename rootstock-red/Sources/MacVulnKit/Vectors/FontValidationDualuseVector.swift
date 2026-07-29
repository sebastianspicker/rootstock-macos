import Foundation
import RootstockCore

/// Path-to-impact: Font validation / ATS dual-use surface.
public struct FontValidationDualuseVector: Check {
    public static let id = "rootstock.vector.delivery.font_validation_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.fontValidationDualuse
        let a = s?.fontToolPaths.count ?? 0
        let b = s?.atsSupportPaths.count ?? 0
        let c = s?.userFontPaths.count ?? 0
        let surface = s?.fontSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.font_validation_dualuse"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "font_validation_dualuse_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.fontToolPaths + s.atsSupportPaths + s.userFontPaths, type: "font_validation_dualuse_path", detail: "Font validation dual-use path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "font_validation_dualuse_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs malicious fonts or disables font validation."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Font validation dual-use with remote amplifier" : "Font validation / ATS dual-use surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1204", "T1189", "T1059"], remediation: [
                "Inventory and baseline Font validation dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs malicious fonts or disables font validation",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
