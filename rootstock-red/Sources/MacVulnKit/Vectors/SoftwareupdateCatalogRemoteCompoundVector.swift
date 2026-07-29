import Foundation
import RootstockCore

/// Wave-16 compound: Software Update catalog × remote/FDA path-to-impact.
public struct SoftwareupdateCatalogRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.persist.softwareupdate_catalog_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.softwareupdateCatalog
        let a = s?.softwareUpdateToolPaths.count ?? 0
        let b = s?.softwareUpdatePrefPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "softwareupdate_catalog_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.softwareUpdateToolPaths + s.softwareUpdatePrefPaths).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Software Update catalog compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never points SUS catalogs at attacker mirrors or tampers with update plists."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Software Update catalog × remote compound" : "Software Update catalog × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1072", "T1195", "T1553"], remediation: [
                "Prioritize hosts co-locating Software Update catalog with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
