import Foundation
import RootstockCore

/// Lab Gatekeeper assessment history review plan - documentation only.
public struct GatekeeperAssessmentHistoryPlanLabAction: LabAction {
    public static let id = "lab.surface.gk_assessment_history_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Gatekeeper assessment history", directory: "gk_assessment-plan", filename: "gk_assessment-plan.md", title: "Gatekeeper assessment history plan", purpose: "Gatekeeper assessment / syspolicyd history depth posture documentation", rules: ["document path/meta inventory only under consent", "never clears Gatekeeper assessments or disables syspolicyd", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE13_GK_ASSESSMENT=1", reviewNoun: "Gatekeeper assessment history", prohibition: "never clears Gatekeeper assessments or disables syspolicyd.")
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
