import Foundation
import RootstockCore

/// Wave-15 compound: Sandbox container depth × remote/FDA path-to-impact.
public struct SandboxContainerDepthRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.sandbox.sandbox_container_depth_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.sandboxContainerDepth
        let a = s?.containerRootPaths.count ?? 0
        let b = s?.sandboxProfilePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "sandbox_container_depth_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.containerRootPaths + s.sandboxProfilePaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Sandbox container depth compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never breaks app sandbox or forges container entitlements."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Sandbox container depth × remote compound" : "Sandbox container depth × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1611", "T1083", "T1005"], remediation: [
                "Prioritize hosts co-locating Sandbox container depth with remote/FDA amplifiers",
                "Use Wave-15 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
