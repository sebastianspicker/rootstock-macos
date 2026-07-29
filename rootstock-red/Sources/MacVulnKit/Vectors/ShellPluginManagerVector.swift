import Foundation
import RootstockCore

/// Path-to-impact: Shell plugin manager dual-use residual.
public struct ShellPluginManagerVector: Check {
    public static let id = "rootstock.vector.persist.shell_plugin_manager"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.shellPluginManager
        let a = s?.omzPaths.count ?? 0
        let b = s?.pluginDirPaths.count ?? 0
        let c = s?.shellInitPaths.count ?? 0
        let surface = s?.shellPluginSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.shell_plugin_manager"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "shell_plugin_manager_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.omzPaths + s.pluginDirPaths + s.shellInitPaths, type: "shell_plugin_manager_path", detail: "Shell plugin manager dual-use path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "shell_plugin_manager_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs oh-my-zsh plugins or rewrites shell init for persistence."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Shell plugin manager dual-use with remote amplifier" : "Shell plugin manager dual-use residual", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1546.004", "T1059.004", "T1546"], remediation: [
                "Inventory and baseline Shell plugin manager dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs oh-my-zsh plugins or rewrites shell init for persistence",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
