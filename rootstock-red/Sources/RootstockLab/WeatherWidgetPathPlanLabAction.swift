import Foundation
import RootstockCore

/// Lab Weather widget residual review plan - documentation only.
public struct WeatherWidgetPathPlanLabAction: LabAction {
    public static let id = "lab.surface.weather_widget_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Weather widget residual", directory: "weather_widget_path-plan", filename: "weather_widget_path-plan.md", title: "Weather widget residual plan", purpose: "Weather / widget data residual plane posture documentation", rules: ["document path/meta inventory only under consent", "never dumps weather personalization data or widget timeline contents", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_WEATHER_WIDGET_PATH=1", reviewNoun: "Weather widget residual", prohibition: "never dumps weather personalization data or widget timeline contents.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
