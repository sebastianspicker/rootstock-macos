import Foundation
import RootstockCore

/// Lab Podcasts path plane review plan - documentation only.
public struct PodcastsPathPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.podcasts_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Podcasts path plane", directory: "podcasts_path_plane-plan", filename: "podcasts_path_plane-plan.md", title: "Podcasts path plane plan", purpose: "Podcasts library path residual posture documentation", rules: ["document path/meta inventory only under consent", "never dumps podcast episode files or account tokens", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_PODCASTS_PATH_PLANE=1", reviewNoun: "Podcasts path plane", prohibition: "never dumps podcast episode files or account tokens.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
