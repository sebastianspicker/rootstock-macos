import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct URLSchemeHandlerPlanLabAction: LabAction {
    public static let id = "lab.surface.url_scheme_handler_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    private static let documentationPlan = DocumentationPlanSpec(focusDefault: "URL scheme / document-handler", directory: "url-scheme-handler-plan", filename: "url-scheme-plan.md", title: "URL scheme / document-handler plan", purpose: "URL scheme / document-handler posture documentation", rules: ["document path/meta inventory only under consent", "never registers schemes or rewrites LaunchServices handlers", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_URLSCHEME=1", reviewNoun: "URL scheme / document-handler", prohibition: "never registers schemes or rewrites LaunchServices handlers")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
