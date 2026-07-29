import Foundation
import RootstockCore

/// Path-to-impact: Compiled AppleScript / OSA delivery residual.
///
/// Research basis: OSA/scpt delivery 2025–26 themes.
/// Safety and behavior: path compounds with remote/FDA amplifiers; never compiles malicious .scpt payloads or executes third-party AppleScripts.
public struct OsascriptScptDeliveryVector: Check {
    public static let id = "rootstock.vector.delivery.osascript_scpt"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.osascriptScptDelivery
        let a = s?.osaToolPaths.count ?? 0
        let b = s?.scriptEditorPaths.count ?? 0
        let c = s?.scptDropHints.count ?? 0
        let surface = s?.scptSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.osascript_scpt_delivery"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true

        var evidence: [Evidence] = [
            Evidence(
                type: "osascript_scpt_summary",
                detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"
            ),
        ]
        if let s {
            for path in (s.osaToolPaths + s.scriptEditorPaths + s.scptDropHints).prefix(12) {
                evidence.append(Evidence(type: "osascript_scpt_path", path: path, detail: "OSA/scpt delivery path"))
            }
            for n in s.notes.prefix(6) {
                evidence.append(Evidence(type: "osascript_scpt_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail: "Assess never compiles malicious .scpt payloads or executes third-party AppleScripts."
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
                    ? "OSA/scpt delivery with remote access amplifier"
                    : "Compiled AppleScript / OSA delivery residual", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1059.002", "T1204", "T1027"], remediation: [
                    "Inventory and baseline OSA/scpt delivery paths via MDM/EDR",
                    "Correlate unexpected path co-presence with delivery timelines",
                    "Prioritize hosts with remote/FDA amplifiers",
                    "OPSEC: Rootstock Red never compiles malicious .scpt payloads or executes third-party AppleScripts",
                ], falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA amplifiers."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"])),
        ]
    }
}
