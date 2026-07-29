import Foundation
import RootstockCore

/// Path-to-impact: Homebrew / third-party package manager dual-use.
public struct HomebrewPackageDualUseVector: Check {
    public static let id = "rootstock.vector.dev.homebrew_package_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.homebrewPackageDualUse
        let a = s?.brewBinaryPaths.count ?? 0
        let b = s?.cellarPaths.count ?? 0
        let c = s?.tapPaths.count ?? 0
        let surface = s?.packageSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.homebrew_package_dualuse"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "homebrew_pkg_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.brewBinaryPaths + s.cellarPaths + s.tapPaths, type: "homebrew_pkg_path", detail: "Homebrew package dual-use path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "homebrew_pkg_note", limit: 6)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs packages or modifies Homebrew formulae."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Homebrew package dual-use with remote access amplifier" : "Homebrew / third-party package manager dual-use", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1072", "T1546", "T1059"], remediation: [
                "Inventory and baseline Homebrew package dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs packages or modifies Homebrew formulae",
            ], falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
