import Foundation
import RootstockCore

/// Lab Notes metadata plane review plan - documentation only.
public struct NotesMetadataPlanePlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.notes_metadata_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
static let documentationPlan = DocumentationPlanSpec(focusDefault: "Notes metadata plane", directory: "notes_metadata_plane-plan", filename: "notes_metadata_plane-plan.md", title: "Notes metadata plane plan", purpose: "Notes.app metadata collection path plane posture documentation", rules: ["document path/meta inventory only under consent", "never reads Notes body contents or exports note secrets", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE14_NOTES_METADATA_PLANE=1", reviewNoun: "Notes metadata plane", prohibition: "never reads Notes body contents or exports note secrets.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
