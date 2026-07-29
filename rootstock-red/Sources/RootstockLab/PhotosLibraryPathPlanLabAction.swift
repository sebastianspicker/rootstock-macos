import Foundation
import RootstockCore

/// Lab Photos library path plane review plan - documentation only.
public struct PhotosLibraryPathPlanLabAction: LabAction {
    public static let id = "lab.surface.photos_library_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Photos library path plane", directory: "photos_library_path-plan", filename: "photos_library_path-plan.md", title: "Photos library path plane plan", purpose: "Photos.app library collection path plane posture documentation", rules: ["document path/meta inventory only under consent", "never reads photo contents or exports Photo Library media", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE15_PHOTOS_LIBRARY_PATH=1", reviewNoun: "Photos library path plane", prohibition: "never reads photo contents or exports Photo Library media.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
