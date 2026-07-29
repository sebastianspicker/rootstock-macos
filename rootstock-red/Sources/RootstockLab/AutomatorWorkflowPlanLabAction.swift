import Foundation
import RootstockCore

/// Lab Automator workflow delivery review plan - documentation only.
public struct AutomatorWorkflowPlanLabAction: LabAction {
    public static let id = "lab.surface.automator_workflow_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Automator workflow delivery", directory: "automator_workflow-plan", filename: "automator_workflow-plan.md", title: "Automator workflow delivery plan", purpose: "Automator workflow delivery residual posture documentation", rules: ["document path/meta inventory only under consent", "never executes Automator workflows or plants malicious .workflow bundles", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE14_AUTOMATOR_WORKFLOW=1", reviewNoun: "Automator workflow delivery", prohibition: "never executes Automator workflows or plants malicious .workflow bundles.")
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
