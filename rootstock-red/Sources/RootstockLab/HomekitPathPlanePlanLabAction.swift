import Foundation
import RootstockCore

/// Lab HomeKit path plane review plan - documentation only.
public struct HomekitPathPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.homekit_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "HomeKit path plane", directory: "homekit_path_plane-plan", filename: "homekit_path_plane-plan.md", title: "HomeKit path plane plan", purpose: "HomeKit residual path plane posture documentation", rules: ["document path/meta inventory only under consent", "never enumerates HomeKit accessory secrets or pairs devices", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_HOMEKIT_PATH_PLANE=1", reviewNoun: "HomeKit path plane", prohibition: "never enumerates HomeKit accessory secrets or pairs devices.")
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
