import Foundation
import RootstockCore

/// Lab Font validation dual-use review plan - documentation only.
public struct FontValidationDualusePlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.font_validation_dualuse_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
static let documentationPlan = DocumentationPlanSpec(focusDefault: "Font validation dual-use", directory: "font_validation_dualuse-plan", filename: "font_validation_dualuse-plan.md", title: "Font validation dual-use plan", purpose: "Font validation / ATS dual-use surface posture documentation", rules: ["document path/meta inventory only under consent", "never installs malicious fonts or disables font validation", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE14_FONT_VALIDATION_DUALUSE=1", reviewNoun: "Font validation dual-use", prohibition: "never installs malicious fonts or disables font validation.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
