import Foundation
import RootstockCore

/// Path-to-impact: XPC Mach service residual depth.
public struct XpcMachServiceDepthVector: Check {
    public static let id = "rootstock.vector.inject.xpc_mach_service_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.xpcMachServiceDepth
        let a = s?.xpcBootstrapPaths.count ?? 0
        let b = s?.machServicePlistPaths.count ?? 0
        let c = s?.xpcToolPaths.count ?? 0
        let surface = s?.xpcMachSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.xpc_mach_service_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "xpc_mach_service_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.xpcBootstrapPaths + s.machServicePlistPaths + s.xpcToolPaths, type: "xpc_mach_service_depth_path", detail: "XPC Mach service depth path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "xpc_mach_service_depth_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never registers XPC services or injects into Mach ports."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "XPC Mach service depth with remote amplifier" : "XPC Mach service residual depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1559", "T1543", "T1055"], remediation: [
                "Inventory and baseline XPC Mach service depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never registers XPC services or injects into Mach ports",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
