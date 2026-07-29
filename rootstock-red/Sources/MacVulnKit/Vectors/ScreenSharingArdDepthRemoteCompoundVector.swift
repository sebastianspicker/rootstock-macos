import Foundation
import RootstockCore

/// Wave-15 compound: Screen Sharing ARD depth × remote/FDA path-to-impact.
public struct ScreenSharingArdDepthRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.network.screen_sharing_ard_depth_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.screenSharingArdDepth
        let a = s?.screenSharingAppPaths.count ?? 0
        let b = s?.ardAgentPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "screen_sharing_ard_depth_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.screenSharingAppPaths + s.ardAgentPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Screen Sharing ARD depth compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never enables Screen Sharing or ARD, never connects to remote desktops."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Screen Sharing ARD depth × remote compound" : "Screen Sharing ARD depth × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1021", "T1219", "T1133"], remediation: [
                "Prioritize hosts co-locating Screen Sharing ARD depth with remote/FDA amplifiers",
                "Use Wave-15 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
