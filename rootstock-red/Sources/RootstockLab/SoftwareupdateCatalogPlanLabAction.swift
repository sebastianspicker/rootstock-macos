import Foundation
import RootstockCore

/// Lab Software Update catalog review plan - documentation only.
public struct SoftwareupdateCatalogPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.softwareupdate_catalog_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
static let documentationPlan = DocumentationPlanSpec(focusDefault: "Software Update catalog", directory: "softwareupdate_catalog-plan", filename: "softwareupdate_catalog-plan.md", title: "Software Update catalog plan", purpose: "Software Update catalog residual surface posture documentation", rules: ["document path/meta inventory only under consent", "never points SUS catalogs at attacker mirrors or tampers with update plists", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_SOFTWAREUPDATE_CATALOG=1", reviewNoun: "Software Update catalog", prohibition: "never points SUS catalogs at attacker mirrors or tampers with update plists.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
