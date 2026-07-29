import Foundation
import RootstockCore

/// Wave-15 compound: VPN config dual-use × remote/FDA path-to-impact.
public struct VpnConfigDualuseRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.network.vpn_config_dualuse_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.vpnConfigDualuse
        let a = s?.vpnFrameworkPaths.count ?? 0
        let b = s?.vpnPrefPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "vpn_config_dualuse_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.vpnFrameworkPaths + s.vpnPrefPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "VPN config dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never installs VPN profiles or rewrites network extension VPN configs."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "VPN config dual-use × remote compound" : "VPN config dual-use × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1133", "T1572", "T1048"], remediation: [
                "Prioritize hosts co-locating VPN config dual-use with remote/FDA amplifiers",
                "Use Wave-15 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
