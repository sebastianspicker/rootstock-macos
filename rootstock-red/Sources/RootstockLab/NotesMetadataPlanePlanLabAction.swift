import Foundation
import RootstockCore

/// Lab Notes metadata plane review plan - documentation only.
public struct NotesMetadataPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.notes_metadata_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Notes metadata plane", directory: "notes_metadata_plane-plan", filename: "notes_metadata_plane-plan.md", title: "Notes metadata plane plan", purpose: "Notes.app metadata collection path plane posture documentation", rules: ["document path/meta inventory only under consent", "never reads Notes body contents or exports note secrets", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE14_NOTES_METADATA_PLANE=1", reviewNoun: "Notes metadata plane", prohibition: "never reads Notes body contents or exports note secrets.")
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
