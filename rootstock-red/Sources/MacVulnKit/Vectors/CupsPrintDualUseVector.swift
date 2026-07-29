import Foundation
import RootstockCore

/// Path-to-impact: CUPS / printer dual-use residual surface.
public struct CupsPrintDualUseVector: Check {
    public static let id = "rootstock.vector.network.cups_print_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.cupsPrintDualUse
        let a = s?.cupsDaemonPaths.count ?? 0
        let b = s?.ppdConfigPaths.count ?? 0
        let c = s?.printToolPaths.count ?? 0
        let surface = s?.printSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.cups_print_dualuse"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "cups_print_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.cupsDaemonPaths + s.ppdConfigPaths + s.printToolPaths, type: "cups_print_path", detail: "CUPS printer dual-use path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "cups_print_note", limit: 6)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never submits print jobs or reconfigures CUPS remotely."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "CUPS printer dual-use with remote access amplifier" : "CUPS / printer dual-use residual surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1040", "T1071", "T1204"], remediation: [
                "Inventory and baseline CUPS printer dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never submits print jobs or reconfigures CUPS remotely",
            ], falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
