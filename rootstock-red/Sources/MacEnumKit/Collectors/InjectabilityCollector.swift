import Foundation
import RootstockCore

/// HR / dangerous entitlement inject surface sample (InjectCheck-class, read-only).
/// Cost `.medium` so standard profile includes it.
public struct InjectabilityCollector: Collector {
    public static let id = "collect.injectability"
    public static let cost: CollectorCost = .medium

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let paths = AppSampleSupport.sampleAppBundlePaths()
        let hits = paths.map { path -> InjectabilityHit in
            let sample = AppSampleSupport.inspectCodesign(path: path)
            return AppSampleSupport.injectabilityHit(from: sample)
        }

        // Prefer reporting apps that actually have risk flags; still keep a short clean sample.
        let flagged = hits.filter { !$0.riskFlags.isEmpty }
        let clean = hits.filter { $0.riskFlags.isEmpty }.prefix(5)
        let report = Array(flagged) + Array(clean)

        var state = CollectedState()
        state.injectabilityHits = report
        state.collectorNotes[Self.id] =
            "sampled \(hits.count) apps; flagged=\(flagged.count) (HR/entitlement surface)"
        return state
    }
}
