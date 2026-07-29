import Foundation
import RootstockCore

/// Lab iMessage path plane review plan - documentation only.
public struct ImessagePathPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.imessage_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "iMessage path plane", directory: "imessage_path_plane-plan", filename: "imessage_path_plane-plan.md", title: "iMessage path plane plan", purpose: "iMessage / Messages path collection plane posture documentation", rules: ["document path/meta inventory only under consent", "never reads Messages database contents or exports chat transcripts", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_IMESSAGE_PATH_PLANE=1", reviewNoun: "iMessage path plane", prohibition: "never reads Messages database contents or exports chat transcripts.")
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
