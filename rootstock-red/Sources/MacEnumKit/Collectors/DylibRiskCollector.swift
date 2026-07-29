import Foundation
import RootstockCore

/// Lightweight weak-dylib load-command scan on sampled app main executables.
/// Cost `.high` so deep/paranoid (and not quick/standard) profiles run it - still real data.
public struct DylibRiskCollector: Collector {
    public static let id = "collect.dylib_risk"
    public static let cost: CollectorCost = .high

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let apps = AppSampleSupport.sampleAppBundlePaths()
        var hits: [DylibRiskHit] = []

        for app in apps {
            guard let exe = AppSampleSupport.mainExecutablePath(for: app) else {
                hits.append(
                    DylibRiskHit(path: app, notes: ["no main executable resolved"])
                )
                continue
            }
            let (weak, notes) = MachOWeakDylibScanner.weakDylibs(at: exe)
            // Record hits with weak loads, or a compact note for scanned clean binaries.
            if !weak.isEmpty || notes.contains(where: { $0.contains("not MH_MAGIC") }) {
                hits.append(
                    DylibRiskHit(
                        path: app,
                        executablePath: exe,
                        weakDylibs: weak,
                        notes: notes
                    )
                )
            } else {
                hits.append(
                    DylibRiskHit(
                        path: app,
                        executablePath: exe,
                        weakDylibs: [],
                        notes: notes.isEmpty ? ["MH_MAGIC_64 scanned; no LC_LOAD_WEAK_DYLIB"] : notes
                    )
                )
            }
        }

        // Cap payload: keep weak-bearing first, then fill.
        let weakBearing = hits.filter { !$0.weakDylibs.isEmpty }
        let rest = hits.filter { $0.weakDylibs.isEmpty }
        let report = Array((weakBearing + rest).prefix(AppSampleSupport.sampleLimit))

        var state = CollectedState()
        state.dylibRiskHits = report
        state.collectorNotes[Self.id] =
            "scanned \(apps.count) apps; weakDylib hits=\(weakBearing.count) (load-command only)"
        return state
    }
}
