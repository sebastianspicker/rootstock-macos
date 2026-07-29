import Foundation
import RootstockCore

/// Lab Books path plane review plan - documentation only.
public struct BooksPathPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.books_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Books path plane", directory: "books_path_plane-plan", filename: "books_path_plane-plan.md", title: "Books path plane plan", purpose: "Books / EPUB path residual plane posture documentation", rules: ["document path/meta inventory only under consent", "never extracts EPUB contents or Books annotations as bulk export", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_BOOKS_PATH_PLANE=1", reviewNoun: "Books path plane", prohibition: "never extracts EPUB contents or Books annotations as bulk export.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
