import Foundation
import RootstockCore

/// Lab Notification Center depth review plan - documentation only.
public struct NotificationCenterDepthPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.notification_center_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
static let documentationPlan = DocumentationPlanSpec(focusDefault: "Notification Center depth", directory: "notification_center_depth-plan", filename: "notification_center_depth-plan.md", title: "Notification Center depth plan", purpose: "Notification Center residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never dumps notification body contents or forges notification payloads", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_NOTIFICATION_CENTER_DEPTH=1", reviewNoun: "Notification Center depth", prohibition: "never dumps notification body contents or forges notification payloads.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
