import Foundation
import RootstockCore

/// Lab Reminders cloud path review plan - documentation only.
public struct RemindersCloudPathPlanLabAction: LabAction {
    public static let id = "lab.surface.reminders_cloud_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Reminders cloud path", directory: "reminders_cloud_path-plan", filename: "reminders_cloud_path-plan.md", title: "Reminders cloud path plan", purpose: "Reminders cloud path residual plane posture documentation", rules: ["document path/meta inventory only under consent", "never reads reminder titles/bodies or exports Reminders databases", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_REMINDERS_CLOUD_PATH=1", reviewNoun: "Reminders cloud path", prohibition: "never reads reminder titles/bodies or exports Reminders databases.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
