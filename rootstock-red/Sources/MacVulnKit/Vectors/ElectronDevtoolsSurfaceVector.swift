import Foundation
import RootstockCore

/// Path-to-impact: Electron / Chromium devtools and inspect-style LOOL surface.
///
/// Research basis: DEF CON / public Electron+TCC research themes; LOOBins dual-use apps.
/// Safety and behavior: runningApps + path heuristics only; no remote-debug attach; ATT&CK + OPSEC.
public struct ElectronDevtoolsSurfaceVector: Check {
    public static let id = "rootstock.vector.lool.electron_devtools_surface"
    public static let cost: CollectorCost = .low

    private static let electronHints = [
        "electron", "chrome", "chromium", "code", "slack", "discord", "teams",
        "figma", "notion", "spotify", "whatsapp", "signal",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard hasSurface(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func hasSurface(_ state: CollectedState) -> Bool {
        let hasElectronApp = state.runningApps.contains { app in
            let blob = (app.name + " " + (app.bundleIdentifier ?? "") + " " + (app.path ?? "")).lowercased()
            return Self.electronHints.contains { blob.contains($0) }
        }
        return hasElectronApp || !Self.noteHits(state).isEmpty
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let hits = state.runningApps.filter { app in
            let blob = (app.name + " " + (app.bundleIdentifier ?? "") + " " + (app.path ?? "")).lowercased()
            return Self.electronHints.contains { blob.contains($0) }
        }
        let noteHits = Self.noteHits(state)
        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "electronLikeRunning=\(hits.count) noteSignals=\(noteHits.count) "
                    + "(no --inspect attach performed)"
            ),
        ]
        for app in hits.prefix(20) {
            evidence.append(
                Evidence(
                    type: "running_app",
                    path: app.path,
                    detail: "name=\(app.name) bundle=\(app.bundleIdentifier ?? "none")"
                )
            )
        }
        for n in noteHits.prefix(10) {
            evidence.append(Evidence(type: "devtools_signal", detail: n))
        }
        evidence.append(
            Evidence(
                type: "technique_note",
                detail:
                    "Public research shows Electron inspect/remote-debug flags can expand attack surface "
                    + "and interact with TCC-sensitive apps - Rootstock only inventories dual-use surface"
            )
        )

        let compoundFDA = state.tcc?.fullDiskAccessLikely == true
        if compoundFDA {
            evidence.append(
                Evidence(type: "compound_fda", detail: "FDA-likely context increases data impact of compromised Electron apps")
            )
        }

        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let hitCount = state.runningApps.filter { app in
            let blob = (app.name + " " + (app.bundleIdentifier ?? "") + " " + (app.path ?? "")).lowercased()
            return electronHints.contains { blob.contains($0) }
        }.count
        let noteHits = noteHits(state)
        let compoundFDA = state.tcc?.fullDiskAccessLikely == true
        let severity: Severity = (!noteHits.isEmpty || (hitCount >= 3 && compoundFDA)) ? .medium : .low
        let title = noteHits.isEmpty
            ? "Electron-like application surface (\(hitCount) running dual-use apps)"
            : "Electron/devtools LOOL surface: explicit inspect/debug signals (\(noteHits.count))"

        return Finding(id: Self.id, title: title, severity: severity, category: .lool, resolution: .init(evidence: evidence, attackTechniques: ["T1218", "T1059", "T1559", "T1083"], remediation: [
                    "Disable developer/remote-debug flags on production Electron deployments",
                    "Keep collaboration apps patched; limit FDA grants to least privilege",
                    "Monitor unusual --inspect / remote-debugging-port process arguments via EDR",
                    "OPSEC: assess does not attach debuggers or inject into Electron renderers",
                ], falsePositiveNotes: "Chrome/Slack/VS Code are common. Presence alone is not malicious; noteSignals indicate stronger evidence."), runtime: .init(confidence: noteHits.isEmpty ? .low : .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "EXEC"]))
    }

    private static func noteHits(_ state: CollectedState) -> [String] {
        guard let note = state.collectorNotes["lool.electron_devtools"] else { return [] }
        return note.split(separator: "|").map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }
}
