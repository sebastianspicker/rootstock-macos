import Foundation
import RootstockCore

/// Wave-12 compound: Dock persistence dual-use × remote/FDA path-to-impact.
public struct DockRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.persist.dock_remote_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.dockPersistenceSurface
        let a = s?.dockPlistPaths.count ?? 0
        let b = s?.recentItemsPaths.count ?? 0
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
                type: "dock_persist_compound",
                detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"
            ),
        ]
        if let s {
            for path in (s.dockPlistPaths + s.recentItemsPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Dock persistence dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never modifies Dock.plist or plants malicious Dock entries."))

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
                    ? "Dock persistence dual-use × remote compound"
                    : "Dock persistence dual-use × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1547", "T1012", "T1083"], remediation: [
                    "Prioritize hosts co-locating Dock persistence dual-use with remote/FDA amplifiers",
                    "Use Wave-12 lab plans under ROE for purple validation",
                    "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
                ], falsePositiveNotes: "Developer hosts may co-locate many dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"])),
        ]
    }
}
