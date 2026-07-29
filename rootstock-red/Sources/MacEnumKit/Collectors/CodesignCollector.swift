import Foundation
import RootstockCore

/// Sample codesign / entitlements for apps under /Applications (Security.framework).
public struct CodesignCollector: Collector {
    public static let id = "collect.codesign"
    public static let cost: CollectorCost = .high

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let paths = AppSampleSupport.sampleAppBundlePaths()
        let samples = paths.map { AppSampleSupport.inspectCodesign(path: $0) }

        var state = CollectedState()
        state.codesignSamples = samples
        let signed = samples.filter { $0.signed == true }.count
        let hr = samples.filter { $0.hardenedRuntime == true }.count
        state.collectorNotes[Self.id] =
            "sampled \(samples.count) apps; signed=\(signed) hardenedRuntime=\(hr)"
        return state
    }
}
