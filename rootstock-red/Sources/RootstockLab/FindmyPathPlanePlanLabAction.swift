import Foundation
import RootstockCore

/// Lab Find My path plane review plan - documentation only.
public struct FindmyPathPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.findmy_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Find My path plane", directory: "findmy_path_plane-plan", filename: "findmy_path_plane-plan.md", title: "Find My path plane plan", purpose: "Find My residual path plane posture documentation", rules: ["document path/meta inventory only under consent", "never queries Find My device locations or dumps owner tokens", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_FINDMY_PATH_PLANE=1", reviewNoun: "Find My path plane", prohibition: "never queries Find My device locations or dumps owner tokens.")
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
