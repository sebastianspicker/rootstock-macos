import Foundation
import RootstockCore

/// Wave-16 compound: AirPlay receiver dual-use × remote/FDA path-to-impact.
public struct AirplayReceiverSurfaceRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.network.airplay_receiver_surface_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.airplayReceiverSurface
        let a = s?.airplayDaemonPaths.count ?? 0
        let b = s?.airplayPrefPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "airplay_receiver_surface_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.airplayDaemonPaths + s.airplayPrefPaths).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "AirPlay receiver dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never enables AirPlay Receiver or spoofs AirPlay targets."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "AirPlay receiver dual-use × remote compound" : "AirPlay receiver dual-use × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1040", "T1021", "T1200"], remediation: [
                "Prioritize hosts co-locating AirPlay receiver dual-use with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
