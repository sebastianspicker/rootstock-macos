import Foundation
import RootstockCore

/// Lab CUPS printer dual-use review plan - documentation only.
public struct CupsPrintPlanLabAction: LabAction {
    public static let id = "lab.surface.cups_print_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "CUPS printer dual-use", directory: "cups_print-plan", filename: "cups_print-plan.md", title: "CUPS printer dual-use plan", purpose: "CUPS / printer dual-use residual surface posture documentation", rules: ["document path/meta inventory only under consent", "never submits print jobs or reconfigures CUPS remotely", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE13_CUPS_PRINT=1", reviewNoun: "CUPS printer dual-use", prohibition: "never submits print jobs or reconfigures CUPS remotely.")
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
