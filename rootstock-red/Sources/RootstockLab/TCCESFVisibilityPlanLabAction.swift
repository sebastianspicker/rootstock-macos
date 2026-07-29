import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct TCCESFVisibilityPlanLabAction: LabAction {
    public static let id = "lab.surface.tcc_esf_visibility_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    private static let documentationPlan = DocumentationPlanSpec(focusDefault: "TCC.db,eslogger,log,visibility-depth", directory: "tcc-esf-visibility-plan", filename: "tcc-esf-visibility-plan.md", title: "TCC/ESF visibility depth plan", purpose: "TCC/ESF visibility depth posture documentation", rules: ["document path/meta inventory only under consent", "never dump TCC.db rows", "never live-subscribe Endpoint Security without separate ROE", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_TCC_ESF_VISIBILITY=1", reviewNoun: "TCC/ESF visibility depth", prohibition: "never dumps TCC.db rows or live-subscribes Endpoint Security")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
