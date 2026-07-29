import Foundation
import RootstockCore

/// Lab Cron/at job depth review plan - documentation only.
public struct CronAtJobDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.cron_at_job_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Cron/at job depth", directory: "cron_at_job_depth-plan", filename: "cron_at_job_depth-plan.md", title: "Cron/at job depth plan", purpose: "Cron / at job dual-use residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never installs cron or at jobs outside the lab root", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE14_CRON_AT_JOB_DEPTH=1", reviewNoun: "Cron/at job depth", prohibition: "never installs cron or at jobs outside the lab root.")
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
