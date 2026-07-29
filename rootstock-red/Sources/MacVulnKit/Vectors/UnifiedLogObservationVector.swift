import Foundation
import RootstockCore

/// Path-to-impact: Unified log / logarchive observation depth.
///
/// Research basis: Unified log observation 2025–26 themes.
/// Safety and behavior: path compounds with remote/FDA amplifiers; never dumps private unified-log message bodies or force-collects other users' logarchives.
public struct UnifiedLogObservationVector: Check {
    public static let id = "rootstock.vector.esf.unified_log_observation"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.unifiedLogObservation
        let a = s?.logToolPaths.count ?? 0
        let b = s?.logarchiveHints.count ?? 0
        let c = s?.privacyPrefPaths.count ?? 0
        let surface = s?.observationSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.unified_log_observation"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true

        var evidence: [Evidence] = [
            Evidence(
                type: "unified_log_summary",
                detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"
            ),
        ]
        if let s {
            for path in (s.logToolPaths + s.logarchiveHints + s.privacyPrefPaths).prefix(12) {
                evidence.append(Evidence(type: "unified_log_path", path: path, detail: "Unified log observation path"))
            }
            for n in s.notes.prefix(6) {
                evidence.append(Evidence(type: "unified_log_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail: "Assess never dumps private unified-log message bodies or force-collects other users' logarchives."
            )
        )

        let severity: Severity
        if remote && fda && a + b >= 3 {
            severity = .high
        } else if remote || fda || a + b >= 2 {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(id: Self.id, title: remote
                    ? "Unified log observation with remote access amplifier"
                    : "Unified log / logarchive observation depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1083", "T1005", "T1562"], remediation: [
                    "Inventory and baseline Unified log observation paths via MDM/EDR",
                    "Correlate unexpected path co-presence with delivery timelines",
                    "Prioritize hosts with remote/FDA amplifiers",
                    "OPSEC: Rootstock Red never dumps private unified-log message bodies or force-collects other users' logarchives",
                ], falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA amplifiers."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"])),
        ]
    }
}
