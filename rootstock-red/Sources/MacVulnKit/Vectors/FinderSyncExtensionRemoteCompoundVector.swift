import Foundation
import RootstockCore

/// Wave-16 compound: Finder Sync dual-use × remote/FDA path-to-impact.
public struct FinderSyncExtensionRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.persist.finder_sync_extension_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.finderSyncExtension
        let a = s?.finderSyncFrameworkPaths.count ?? 0
        let b = s?.appScriptPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "finder_sync_extension_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.finderSyncFrameworkPaths + s.appScriptPaths).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Finder Sync dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never installs Finder Sync extensions or rewrites Finder preferences for abuse."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Finder Sync dual-use × remote compound" : "Finder Sync dual-use × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1546", "T1176", "T1059"], remediation: [
                "Prioritize hosts co-locating Finder Sync dual-use with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
