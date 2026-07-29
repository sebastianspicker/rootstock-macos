import Foundation
import RootstockCore

/// Wave-12 compound: Unified log observation × remote/FDA path-to-impact.
public struct UnifiedLogSensorCompoundVector: Check {
    public static let id = "rootstock.vector.esf.unified_log_sensor_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.unifiedLogObservation
        let a = s?.logToolPaths.count ?? 0
        let b = s?.logarchiveHints.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin =
            state.esf?.clientPaths.isEmpty == true
            || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "unified_log_compound",
                detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"
            ),
        ]
        if let s {
            for path in (s.logToolPaths + s.logarchiveHints).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Unified log observation compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never dumps private unified-log message bodies or force-collects other users' logarchives."))

        let severity: Severity
        if remote && fda {
            severity = .high
        } else if remote || fda || sensorThin {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(id: Self.id, title: remote
                    ? "Unified log observation × remote compound"
                    : "Unified log observation × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1083", "T1005", "T1562"], remediation: [
                    "Prioritize hosts co-locating Unified log observation with remote/FDA amplifiers",
                    "Use Wave-12 lab plans under ROE for purple validation",
                    "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
                ], falsePositiveNotes: "Developer hosts may co-locate many dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"])),
        ]
    }
}
