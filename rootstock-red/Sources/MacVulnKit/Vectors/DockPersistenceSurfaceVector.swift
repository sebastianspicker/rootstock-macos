import Foundation
import RootstockCore

/// Path-to-impact: Dock persistent apps / recent items dual-use.
///
/// Research basis: Dock persistence dual-use 2025–26 themes.
/// Safety and behavior: path compounds with remote/FDA amplifiers; never modifies Dock.plist or plants malicious Dock entries.
public struct DockPersistenceSurfaceVector: Check {
    public static let id = "rootstock.vector.persist.dock_persistence_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.dockPersistenceSurface
        let a = s?.dockPlistPaths.count ?? 0
        let b = s?.recentItemsPaths.count ?? 0
        let c = s?.dockDbHints.count ?? 0
        let surface = s?.dockSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.dock_persistence_surface"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true

        var evidence: [Evidence] = [
            Evidence(
                type: "dock_persist_summary",
                detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"
            ),
        ]
        if let s {
            for path in (s.dockPlistPaths + s.recentItemsPaths + s.dockDbHints).prefix(12) {
                evidence.append(Evidence(type: "dock_persist_path", path: path, detail: "Dock persistence dual-use path"))
            }
            for n in s.notes.prefix(6) {
                evidence.append(Evidence(type: "dock_persist_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail: "Assess never modifies Dock.plist or plants malicious Dock entries."
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
                    ? "Dock persistence dual-use with remote access amplifier"
                    : "Dock persistent apps / recent items dual-use", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1547", "T1012", "T1083"], remediation: [
                    "Inventory and baseline Dock persistence dual-use paths via MDM/EDR",
                    "Correlate unexpected path co-presence with delivery timelines",
                    "Prioritize hosts with remote/FDA amplifiers",
                    "OPSEC: Rootstock Red never modifies Dock.plist or plants malicious Dock entries",
                ], falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA amplifiers."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"])),
        ]
    }
}
