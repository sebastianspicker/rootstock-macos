import Foundation
import RootstockCore

/// Existence of common credential paths - never reads secret material.
public struct CredPathsCollector: Collector {
    public static let id = "collect.cred_paths"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let candidates: [(String, String)] = [
            ("ssh", home.appendingPathComponent(".ssh").path),
            ("aws", home.appendingPathComponent(".aws").path),
            ("azure", home.appendingPathComponent(".azure").path),
            ("gcloud", home.appendingPathComponent(".config/gcloud").path),
            ("kube", home.appendingPathComponent(".kube").path),
        ]
        let fm = FileManager.default
        let hits = candidates.map { kind, path in
            CredPathHit(kind: kind, path: path, exists: fm.fileExists(atPath: path))
        }
        var state = CollectedState()
        state.credPaths = hits
        state.collectorNotes[Self.id] = "path existence only; no secret reads"
        return state
    }
}
