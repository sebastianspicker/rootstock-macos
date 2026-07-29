import Foundation
import RootstockCore

/// Path-to-impact: VPN configuration dual-use residual surface.
public struct VpnConfigDualuseVector: Check {
    public static let id = "rootstock.vector.network.vpn_config_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.vpnConfigDualuse
        let a = s?.vpnFrameworkPaths.count ?? 0
        let b = s?.vpnPrefPaths.count ?? 0
        let c = s?.vpnToolPaths.count ?? 0
        let surface = s?.vpnSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.vpn_config_dualuse"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "vpn_config_dualuse_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.vpnFrameworkPaths + s.vpnPrefPaths + s.vpnToolPaths, type: "vpn_config_dualuse_path", detail: "VPN config dual-use path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "vpn_config_dualuse_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs VPN profiles or rewrites network extension VPN configs."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "VPN config dual-use with remote amplifier" : "VPN configuration dual-use residual surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1133", "T1572", "T1048"], remediation: [
                "Inventory and baseline VPN config dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs VPN profiles or rewrites network extension VPN configs",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
