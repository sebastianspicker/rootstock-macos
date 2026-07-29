import Foundation
import RootstockCore

/// Lab Screen Sharing ARD depth review plan - documentation only.
public struct ScreenSharingArdDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.screen_sharing_ard_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Screen Sharing ARD depth", directory: "screen_sharing_ard_depth-plan", filename: "screen_sharing_ard_depth-plan.md", title: "Screen Sharing ARD depth plan", purpose: "Screen Sharing / ARD residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never enables Screen Sharing or ARD, never connects to remote desktops", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE15_SCREEN_SHARING_ARD_DEPTH=1", reviewNoun: "Screen Sharing ARD depth", prohibition: "never enables Screen Sharing or ARD, never connects to remote desktops.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
