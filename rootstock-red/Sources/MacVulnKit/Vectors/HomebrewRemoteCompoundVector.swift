import Foundation
import RootstockCore

/// Wave-13 compound: Homebrew package dual-use × remote/FDA path-to-impact.
public struct HomebrewRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.dev.homebrew_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.homebrewPackageDualUse
        let a = s?.brewBinaryPaths.count ?? 0
        let b = s?.cellarPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "homebrew_pkg_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.brewBinaryPaths + s.cellarPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Homebrew package dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never installs packages or modifies Homebrew formulae."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Homebrew package dual-use × remote compound" : "Homebrew package dual-use × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1072", "T1546", "T1059"], remediation: [
                "Prioritize hosts co-locating Homebrew package dual-use with remote/FDA amplifiers",
                "Use Wave-13 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
