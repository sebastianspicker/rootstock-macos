import Foundation
import RootstockCore

/// Lab Mail rules automation review plan - documentation only.
public struct MailRulesAutomationPlanLabAction: LabAction {
    public static let id = "lab.surface.mail_rules_automation_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    private static let documentationPlan = DocumentationPlanSpec(
        focusDefault: "Mail rules automation",
        directory: "mail_rules-plan",
        filename: "mail_rules-plan.md",
        title: "Mail rules automation plan",
        purpose: "Mail rules / Apple Mail automation persistence posture documentation",
        rules: ["document path/meta inventory only under consent", "never reads Mail contents or modifies user Mail rules", "purple: validate expected telemetry under ROE only"],
        markerFlag: "ROOTSTOCK_RED_LAB_WAVE12_MAIL_RULES=1",
        reviewNoun: "Mail rules automation",
        prohibition: "never reads Mail contents or modifies user Mail rules."
    )

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

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
