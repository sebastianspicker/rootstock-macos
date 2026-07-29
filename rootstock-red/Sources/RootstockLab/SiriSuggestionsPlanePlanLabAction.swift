import Foundation
import RootstockCore

/// Lab Siri Suggestions residual review plan - documentation only.
public struct SiriSuggestionsPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.siri_suggestions_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Siri Suggestions residual", directory: "siri_suggestions_plane-plan", filename: "siri_suggestions_plane-plan.md", title: "Siri Suggestions residual plan", purpose: "Siri / Suggestions data-access residual posture documentation", rules: ["document path/meta inventory only under consent", "never dumps Siri transcripts or Suggestions databases contents", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_SIRI_SUGGESTIONS_PLANE=1", reviewNoun: "Siri Suggestions residual", prohibition: "never dumps Siri transcripts or Suggestions databases contents.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
