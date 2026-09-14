import Foundation
import RootstockCore

/// Lab LS QuarantineEvents depth review plan - documentation only.
public struct LsQuarantineDbDepthPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.ls_quarantine_db_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
static let documentationPlan = DocumentationPlanSpec(focusDefault: "LS QuarantineEvents depth", directory: "ls_quarantine_db_depth-plan", filename: "ls_quarantine_db_depth-plan.md", title: "LS QuarantineEvents depth plan", purpose: "LaunchServices QuarantineEvents DB residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never deletes QuarantineEvents rows or clears LS quarantine history", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE14_LS_QUARANTINE_DB_DEPTH=1", reviewNoun: "LS QuarantineEvents depth", prohibition: "never deletes QuarantineEvents rows or clears LS quarantine history.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
