import Foundation
import RootstockCore

/// Path-to-impact: Python runtime dual-use residual surface.
public struct PythonRuntimeDualuseVector: Check {
    public static let id = "rootstock.vector.lool.python_runtime_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.pythonRuntimeDualuse
        let a = s?.pythonBinaryPaths.count ?? 0
        let b = s?.sitePackagePaths.count ?? 0
        let c = s?.pythonFrameworkPaths.count ?? 0
        let surface = s?.pythonSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.python_runtime_dualuse"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "python_runtime_dualuse_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.pythonBinaryPaths + s.sitePackagePaths + s.pythonFrameworkPaths, type: "python_runtime_dualuse_path", detail: "Python runtime dual-use path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "python_runtime_dualuse_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never executes third-party Python payloads or drops malicious site-packages."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Python runtime dual-use with remote amplifier" : "Python runtime dual-use residual surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1059.006", "T1059", "T1204"], remediation: [
                "Inventory and baseline Python runtime dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never executes third-party Python payloads or drops malicious site-packages",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
