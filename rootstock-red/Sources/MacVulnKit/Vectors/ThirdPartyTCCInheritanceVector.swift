import Foundation
import RootstockCore

/// Path-to-impact: third-party TCC-inheritance / embedded-interpreter class.
///
/// Research basis: Electron/TCC inheritance discussions; thick-client dual-use execution.
/// Safety and behavior: path samples + TCC domain compound; never forges grants.
public struct ThirdPartyTCCInheritanceVector: Check {
    private struct InheritanceCounts {
        let thick: Int
        let interpreters: Int
        let electron: Int
    }
    public static let id = "rootstock.vector.tcc.third_party_inheritance"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard Self.hasInheritanceSurface(state), Self.hasInheritanceSignal(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }


    private static func counts(_ state: CollectedState) -> InheritanceCounts {
        let plane = state.thirdPartyTCCInheritance
        return InheritanceCounts(
            thick: plane?.thickClientAppPaths.count ?? 0,
            interpreters: plane?.embeddedInterpreterPaths.count ?? 0,
            electron: plane?.electronHelperPaths.count ?? 0
        )
    }

    private static func hasInheritanceSurface(_ state: CollectedState) -> Bool {
        let counts = counts(state)
        return state.thirdPartyTCCInheritance?.inheritanceSurfacePresent == true
            || (counts.thick > 0 && counts.interpreters > 0)
            || state.collectorNotes["collect.third_party_tcc_inheritance"] != nil
    }

    private static func axSignals(_ state: CollectedState) -> Bool {
        state.tcc?.domainSignals.contains {
            $0.lowercased().contains("screen") || $0.lowercased().contains("accessib")
                || $0.lowercased().contains("automation")
        } ?? false
    }

    private static func hasInheritanceSignal(_ state: CollectedState) -> Bool {
        let counts = counts(state)
        return counts.thick >= 1 && (counts.interpreters >= 1 || counts.electron >= 1
            || state.tcc?.fullDiskAccessLikely == true || axSignals(state) || counts.thick >= 2)
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let counts = Self.counts(state), fda = state.tcc?.fullDiskAccessLikely == true, ax = Self.axSignals(state)
        let sensitive = state.browserMeta.contains(where: \.exists) || state.credPaths.contains(where: \.exists)
        var evidence: [Evidence] = [Evidence(type: "tcc_inheritance_summary", detail: "thick=\(counts.thick) interpreters=\(counts.interpreters) electron=\(counts.electron) " + "fda=\(fda) axSignals=\(ax) sensitive=\(sensitive)")]
        if let plane = state.thirdPartyTCCInheritance {
            for path in (plane.thickClientAppPaths + plane.embeddedInterpreterPaths).prefix(12) { evidence.append(Evidence(type: "inheritance_path", path: path, detail: "TCC inheritance class path")) }
            for note in plane.notes.prefix(6) { evidence.append(Evidence(type: "inheritance_note", detail: note)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never forges TCC grants, never strips entitlements, " + "never weaponizes Electron/interpreter inheritance bypasses."))
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let counts = counts(state), fda = state.tcc?.fullDiskAccessLikely == true, ax = axSignals(state)
        let severity: Severity = (fda || ax) && (counts.interpreters >= 1 || counts.electron >= 1) ? .medium : .low
        return Finding(id: Self.id, title: counts.electron > 0 ? "Third-party TCC inheritance surface with Electron/embedded helpers" : "Third-party TCC inheritance / embedded-interpreter surface", severity: severity, category: .tcc, resolution: .init(evidence: evidence, attackTechniques: ["T1059", "T1559", "T1548"], remediation: ["Review TCC grants for high-value thick clients (Screen, Accessibility, FDA)", "Prefer sandboxed / Hardened Runtime builds; limit embedded debug interpreters", "Monitor child process trees from Electron shells and IDE helpers", "OPSEC: Rootstock Red does not forge TCC grants or deliver inheritance exploits"], falsePositiveNotes: "Electron apps and host interpreters are common on developer workstations. " + "Prioritize production hosts with broad TCC grants on thick clients."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 22, tccDomains: fda ? ["FullDiskAccess"] : (ax ? ["Accessibility"] : []), esfExpected: ["OPEN", "EXEC"]))
    }
}
