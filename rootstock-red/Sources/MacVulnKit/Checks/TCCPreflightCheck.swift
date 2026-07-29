/// Cluster/check: TCCPreflightCheck - multi-signal posture ranking for assess pipeline.
import Foundation
import RootstockCore

public struct TCCPreflightCheck: Check {
    public static let id = "rootstock.check.tcc.preflight_summary"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let tcc = state.tcc else { return [] }
        var evidence = tcc.notes.map { Evidence(type: "tcc_note", detail: $0) }
        evidence.append(Evidence(type: "probe", detail: "method=\(tcc.probeMethod)"))
        var remediation: [String] = [
            "Non-prompting assess probes only - Rootstock Red will not trigger TCC dialogs in audit mode",
            "Map TCC domains (FDA, Screen Recording, Accessibility) before deeper collection",
        ]
        let presentation = Self.presentation(for: tcc.fullDiskAccessLikely)
        remediation.insert(presentation.remediation, at: 0)
        evidence.append(Evidence(type: "fda", detail: presentation.detail))
        if !state.deniedCollectors.isEmpty {
            evidence.append(Evidence(type: "denied_collectors", detail: state.deniedCollectors.sorted().joined(separator: ",")))
        }
        return [Finding(id: Self.id, title: presentation.title, severity: .info, category: .tcc, resolution: .init(evidence: evidence, attackTechniques: ["T1069", "T1005"], remediation: remediation, falsePositiveNotes: "User TCC.db readability and path heuristics are incomplete on enterprise fleets; false positives/negatives expected without Privacy Preferences Policy Control (PPPC) context"), runtime: .init(confidence: presentation.confidence, dryRunSafe: true, opsecScore: 12, tccDomains: ["FullDiskAccess"], esfExpected: ["OPEN"]))]
    }

    private struct Presentation { let detail: String; let title: String; let confidence: Confidence; let remediation: String }

    private static func presentation(for fda: Bool?) -> Presentation {
        if fda == true { return Presentation(detail: "fullDiskAccessLikely=true", title: "TCC preflight: Full Disk Access appears granted (heuristic)", confidence: .medium, remediation: "FDA-capable context increases sensitivity of path reads; keep scope ROE-bound") }
        if fda == false { return Presentation(detail: "fullDiskAccessLikely=false", title: "TCC preflight: Full Disk Access not indicated", confidence: .low, remediation: "Without FDA, many user TCC-protected paths will be denied - treat denials as data") }
        return Presentation(detail: "fullDiskAccessLikely=unknown", title: "TCC preflight: FDA status unknown (non-prompting probe)", confidence: .low, remediation: "FDA unknown - do not assume access; collectors record TCC denials in deniedCollectors")
    }
}
