import Foundation
import RootstockCore

/// Path-to-impact: Books / EPUB path residual plane.
public struct BooksPathPlaneVector: Check {
    public static let id = "rootstock.vector.data.books_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.booksPathPlane
        let a = s?.booksAppPaths.count ?? 0
        let b = s?.booksContainerPaths.count ?? 0
        let c = s?.booksPrefPaths.count ?? 0
        let surface = s?.booksSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.books_path_plane"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "books_path_plane_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.booksAppPaths + s.booksContainerPaths + s.booksPrefPaths, type: "books_path_plane_path", detail: "Books path plane path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "books_path_plane_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never extracts EPUB contents or Books annotations as bulk export."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Books path plane with remote amplifier" : "Books / EPUB path residual plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1083", "T1119"], remediation: [
                "Inventory and baseline Books path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never extracts EPUB contents or Books annotations as bulk export",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
