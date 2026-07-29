import Foundation
import RootstockCore

/// Wave-15 compound: Photos library path plane × remote/FDA path-to-impact.
public struct PhotosLibraryPathRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.photos_library_path_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.photosLibraryPath
        let a = s?.photosAppPaths.count ?? 0
        let b = s?.photosLibraryPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "photos_library_path_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.photosAppPaths + s.photosLibraryPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Photos library path plane compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never reads photo contents or exports Photo Library media."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Photos library path plane × remote compound" : "Photos library path plane × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1119", "T1530"], remediation: [
                "Prioritize hosts co-locating Photos library path plane with remote/FDA amplifiers",
                "Use Wave-15 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
