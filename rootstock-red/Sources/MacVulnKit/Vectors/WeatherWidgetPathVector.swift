import Foundation
import RootstockCore

/// Path-to-impact: Weather / widget data residual plane.
public struct WeatherWidgetPathVector: Check {
    public static let id = "rootstock.vector.data.weather_widget_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.weatherWidgetPath
        let a = s?.weatherAppPaths.count ?? 0
        let b = s?.weatherContainerPaths.count ?? 0
        let c = s?.widgetServicePaths.count ?? 0
        let surface = s?.weatherSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.weather_widget_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "weather_widget_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.weatherAppPaths + s.weatherContainerPaths + s.widgetServicePaths, type: "weather_widget_path_path", detail: "Weather widget residual path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "weather_widget_path_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps weather personalization data or widget timeline contents."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Weather widget residual with remote amplifier" : "Weather / widget data residual plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1083", "T1518"], remediation: [
                "Inventory and baseline Weather widget residual paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps weather personalization data or widget timeline contents",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
