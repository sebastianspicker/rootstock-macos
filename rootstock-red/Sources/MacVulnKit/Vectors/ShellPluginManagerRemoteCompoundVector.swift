import Foundation
import RootstockCore

/// Wave-15 compound: Shell plugin manager dual-use × remote/FDA path-to-impact.
public struct ShellPluginManagerRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.persist.shell_plugin_manager_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.shellPluginManager
        let a = s?.omzPaths.count ?? 0
        let b = s?.pluginDirPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "shell_plugin_manager_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.omzPaths + s.pluginDirPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Shell plugin manager dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never installs oh-my-zsh plugins or rewrites shell init for persistence."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Shell plugin manager dual-use × remote compound" : "Shell plugin manager dual-use × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1546.004", "T1059.004", "T1546"], remediation: [
                "Prioritize hosts co-locating Shell plugin manager dual-use with remote/FDA amplifiers",
                "Use Wave-15 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
