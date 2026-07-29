import Foundation
import RootstockCore

/// Lab Health path plane review plan - documentation only.
public struct HealthPathPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.health_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Health path plane", directory: "health_path_plane-plan", filename: "health_path_plane-plan.md", title: "Health path plane plan", purpose: "Health app residual path plane posture documentation", rules: ["document path/meta inventory only under consent", "never exports HealthKit samples or medical records", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_HEALTH_PATH_PLANE=1", reviewNoun: "Health path plane", prohibition: "never exports HealthKit samples or medical records.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(
            actionId: Self.id,
            consent: Self.consent,
            spec: Self.documentationPlan,
            request: request,
            context: context
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
