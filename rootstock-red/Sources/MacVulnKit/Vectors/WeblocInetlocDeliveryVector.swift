import Foundation
import RootstockCore

/// Path-to-impact: Webloc / Internet Location file delivery.
///
/// Research basis: Webloc/inetloc delivery 2025–26 themes.
/// Safety and behavior: path compounds with remote/FDA amplifiers; never crafts phishing webloc/inetloc payloads or rewrites Internet Location files.
public struct WeblocInetlocDeliveryVector: Check {
    public static let id = "rootstock.vector.delivery.webloc_inetloc"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.weblocInetlocDelivery
        let a = s?.weblocSamplePaths.count ?? 0
        let b = s?.inetlocSamplePaths.count ?? 0
        let c = s?.dropFolderHints.count ?? 0
        let surface = s?.deliverySurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.webloc_inetloc_delivery"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true

        var evidence: [Evidence] = [
            Evidence(
                type: "webloc_inetloc_summary",
                detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"
            ),
        ]
        if let s {
            for path in (s.weblocSamplePaths + s.inetlocSamplePaths + s.dropFolderHints).prefix(12) {
                evidence.append(Evidence(type: "webloc_inetloc_path", path: path, detail: "Webloc/inetloc delivery path"))
            }
            for n in s.notes.prefix(6) {
                evidence.append(Evidence(type: "webloc_inetloc_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail: "Assess never crafts phishing webloc/inetloc payloads or rewrites Internet Location files."
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
                    ? "Webloc/inetloc delivery with remote access amplifier"
                    : "Webloc / Internet Location file delivery", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1204", "T1566", "T1105"], remediation: [
                    "Inventory and baseline Webloc/inetloc delivery paths via MDM/EDR",
                    "Correlate unexpected path co-presence with delivery timelines",
                    "Prioritize hosts with remote/FDA amplifiers",
                    "OPSEC: Rootstock Red never crafts phishing webloc/inetloc payloads or rewrites Internet Location files",
                ], falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA amplifiers."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"])),
        ]
    }
}
