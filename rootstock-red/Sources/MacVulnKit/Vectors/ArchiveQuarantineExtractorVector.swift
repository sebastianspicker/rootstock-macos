import Foundation
import RootstockCore

/// Path-to-impact: third-party archive extractor quarantine non-inheritance surface.
///
/// Research basis: Unit 42 / Jamf archive extractor Gatekeeper research.
/// Safety and behavior: typed compound with GK/remote; never strips quarantine or crafts bypass archives.
public struct ArchiveQuarantineExtractorVector: Check {
    public static let id = "rootstock.vector.codesign.archive_quarantine_extractor"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard shouldReport(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let extractor = state.archiveQuarantineExtractor
        let third = extractor?.thirdPartyExtractorPaths.count ?? 0
        let stock = extractor?.stockExtractorPaths.count ?? 0
        let drops = extractor?.archiveDropHints.count ?? 0
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let gkOff = state.protections?.gatekeeperEnabled == false
        var evidence = [Evidence(
            type: "extractor_summary",
            detail: "thirdParty=\(third) stock=\(stock) drops=\(drops) remote=\(remote) gkOff=\(gkOff)"
        )]
        if let extractor {
            for path in (extractor.thirdPartyExtractorPaths + extractor.stockExtractorPaths).prefix(12) {
                evidence.append(Evidence(type: "extractor_path", path: path, detail: "archive extractor"))
            }
            for note in extractor.notes.prefix(6) {
                evidence.append(Evidence(type: "extractor_note", detail: note))
            }
        }
        evidence.append(Evidence(
            type: "honesty",
            detail: "Assess never strips com.apple.quarantine, never crafts clever archives, never delivers Gatekeeper bypass recipes."
        ))
        return evidence
    }

    private func shouldReport(_ state: CollectedState) -> Bool {
        let extractor = state.archiveQuarantineExtractor
        let third = extractor?.thirdPartyExtractorPaths.count ?? 0
        let stock = extractor?.stockExtractorPaths.count ?? 0
        let surface = extractor?.extractorSurfacePresent == true || third > 0 || stock >= 3
        return (surface || state.collectorNotes["collect.archive_quarantine_extractor"] != nil)
            && (third >= 1 || stock >= 2)
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let extractor = state.archiveQuarantineExtractor
        let third = extractor?.thirdPartyExtractorPaths.count ?? 0
        let stock = extractor?.stockExtractorPaths.count ?? 0
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let gkOff = state.protections?.gatekeeperEnabled == false
        let severity: Severity = third >= 1 && (gkOff || remote)
            ? .high
            : (third >= 1 || (stock >= 3 && gkOff) ? .medium : .low)
        return Finding(id: Self.id, title: third >= 1
                ? "Third-party archive extractors expand quarantine non-inheritance surface"
                : "Archive extractor / quarantine inheritance posture", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1204", "T1553.001", "T1036"], remediation: [
                "Prefer Archive Utility / managed extractors that preserve quarantine attributes",
                "Train users against unpacking untrusted archives from email/web with third-party tools",
                "Monitor process trees where extractors write into Downloads then spawn unsigned apps",
                "OPSEC: Rootstock Red does not craft bypass archives or strip quarantine xattrs",
            ], falsePositiveNotes: "Stock tar/unzip/ditto ship with macOS. Elevate priority when third-party extractors co-present with Gatekeeper-off or remote access."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 18, esfExpected: ["OPEN", "WRITE", "EXEC"]))
    }
}
