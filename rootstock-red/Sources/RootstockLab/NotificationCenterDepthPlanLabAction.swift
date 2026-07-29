import Foundation
import RootstockCore

/// Lab Notification Center depth review plan - documentation only.
public struct NotificationCenterDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.notification_center_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Notification Center depth", directory: "notification_center_depth-plan", filename: "notification_center_depth-plan.md", title: "Notification Center depth plan", purpose: "Notification Center residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never dumps notification body contents or forges notification payloads", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_NOTIFICATION_CENTER_DEPTH=1", reviewNoun: "Notification Center depth", prohibition: "never dumps notification body contents or forges notification payloads.")
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
