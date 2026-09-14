import Foundation
import RootstockCore

/// Lab Calendar/Reminders automation review plan - documentation only.
public struct CalendarRemindersPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.calendar_reminders_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
static let documentationPlan = DocumentationPlanSpec(focusDefault: "Calendar/Reminders automation", directory: "calendar_reminders-plan", filename: "calendar_reminders-plan.md", title: "Calendar/Reminders automation plan", purpose: "Calendar / Reminders automation lateral surface posture documentation", rules: ["document path/meta inventory only under consent", "never reads event contents or creates malicious calendar invites", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE13_CALENDAR_REMINDERS=1", reviewNoun: "Calendar/Reminders automation", prohibition: "never reads event contents or creates malicious calendar invites.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
