import Foundation
import RootstockCore

/// Path-to-impact: Full Disk Access / TCC posture as a data-access and lateral pivot.
///
/// Emits one ranked vector with ATT&CK mappings, non-prompting probes, and
/// remediation. It does not dump TCC databases.
public struct TCCFDAPermissionPivotVector: Check {
    public static let id = "rootstock.vector.tcc.fda_permission_pivot"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let tcc = state.tcc else { return [] }
        let sensitiveContext = Self.sensitiveContext(in: state)
        guard Self.shouldEmit(fda: tcc.fullDiskAccessLikely, hasSensitiveContext: sensitiveContext.hasSignals) else { return [] }
        return [Self.finding(tcc: tcc, sensitiveContext: sensitiveContext, state: state)]
    }

    private struct SensitiveContext { let hasCredOrBrowser: Bool; let hasSignals: Bool }
    private struct Presentation { let title: String; let severity: Severity; let confidence: Confidence; let opsec: Int }

    private static func sensitiveContext(in state: CollectedState) -> SensitiveContext {
        let hasCredOrBrowser = state.credPaths.contains(where: \.exists) || state.browserMeta.contains(where: \.exists)
        return SensitiveContext(hasCredOrBrowser: hasCredOrBrowser, hasSignals: hasCredOrBrowser || !state.deniedCollectors.isEmpty)
    }

    private static func shouldEmit(fda: Bool?, hasSensitiveContext: Bool) -> Bool {
        fda == true || hasSensitiveContext
    }

    private static func finding(tcc: TCCState, sensitiveContext: SensitiveContext, state: CollectedState) -> Finding {
        var evidence = [Evidence(type: "probe", detail: "method=\(tcc.probeMethod)"), Evidence(type: "fda", detail: "fullDiskAccessLikely=\(tcc.fullDiskAccessLikely.rootstockDescribe)")]
        evidence += tcc.notes.prefix(12).map { Evidence(type: "tcc_note", detail: $0) }
        if !state.deniedCollectors.isEmpty { evidence.append(Evidence(type: "denied_collectors", detail: state.deniedCollectors.sorted().joined(separator: ","))) }
        if sensitiveContext.hasCredOrBrowser { evidence.append(Evidence(type: "pivot_targets", detail: "credPathsPresent=\(state.credPaths.filter(\.exists).count) browserMetaPresent=\(state.browserMeta.filter(\.exists).count) (path metadata only - no secret/cookie material)")) }
        let presentation = self.presentation(for: tcc.fullDiskAccessLikely)
        return Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .tcc, resolution: .init(evidence: evidence, attackTechniques: ["T1069", "T1005", "T1530", "T1083"], remediation: ["Revoke unexpected Full Disk Access grants in System Settings → Privacy & Security", "Prefer PPPC configuration profiles for enterprise allowlists over ad-hoc FDA", "Treat FDA-capable tools as high-value; monitor OPEN of TCC-protected roots", "OPSEC: Rootstock Red uses non-prompting probes only - never force TCC dialogs in assess"], falsePositiveNotes: "FDA heuristics (path listability) are incomplete; enterprise PPPC/MDM may grant or deny outside user TCC.db visibility. Presence of deniedCollectors is expected without FDA."), runtime: .init(confidence: presentation.confidence, dryRunSafe: true, opsecScore: presentation.opsec, tccDomains: ["FullDiskAccess"], esfExpected: ["OPEN"]))
    }

    private static func presentation(for fda: Bool?) -> Presentation {
        if fda == true { return Presentation(title: "TCC pivot: Full Disk Access likely - broad user-data access surface", severity: .high, confidence: .medium, opsec: 35) }
        if fda == false { return Presentation(title: "TCC friction pivot: FDA not indicated while sensitive paths/collectors constrained", severity: .medium, confidence: .medium, opsec: 22) }
        return Presentation(title: "TCC posture unknown with sensitive path-to-impact signals present", severity: .low, confidence: .low, opsec: 18)
    }

}
