import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct WeblocInetlocPlanLabAction: LabAction {
    public static let id = "lab.surface.webloc_inetloc_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Webloc/inetloc delivery", directory: "webloc_inetloc-plan", filename: "webloc_inetloc-plan.md", title: "Webloc/inetloc delivery plan", purpose: "Webloc / Internet Location file delivery posture documentation", rules: ["document path/meta inventory only under consent", "never crafts phishing webloc/inetloc payloads or rewrites Internet Location files", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE12_WEBLOC_INETLOC=1", reviewNoun: "Webloc/inetloc delivery", prohibition: "never crafts phishing webloc/inetloc payloads or rewrites Internet Location files")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
