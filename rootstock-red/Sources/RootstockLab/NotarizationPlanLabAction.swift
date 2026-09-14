import Foundation
import RootstockCore

/// Lab notarization / stapling review plan - documentation + reversible marker only.
public struct NotarizationPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.notarization_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    static let documentationPlan = DocumentationPlanSpec(focusDefault: "stapler,spctl,delivery-artifacts", directory: "notarization-plan", filename: "notarization-plan.md", title: "notarization plan", purpose: "delivery-trust / stapling posture documentation", rules: ["document spctl/stapler tooling and delivery artifacts only under consent", "never forge notarization tickets", "never provide Gatekeeper bypass recipes", "purple: expect OPEN of Downloads/DMG paths if inspected under ROE"], markerFlag: "ROOTSTOCK_RED_LAB_NOTARIZATION=1", reviewNoun: "notarization/stapling", prohibition: "Never forges tickets or bypasses Gatekeeper.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
