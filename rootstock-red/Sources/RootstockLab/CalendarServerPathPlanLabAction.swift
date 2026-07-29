import Foundation
import RootstockCore

/// Lab Calendar CalDAV residual review plan - documentation only.
public struct CalendarServerPathPlanLabAction: LabAction {
    public static let id = "lab.surface.calendar_server_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Calendar CalDAV residual", directory: "calendar_server_path-plan", filename: "calendar_server_path-plan.md", title: "Calendar CalDAV residual plan", purpose: "Calendar server / CalDAV residual surface posture documentation", rules: ["document path/meta inventory only under consent", "never reads calendar event bodies or credentials from CalDAV stores", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_CALENDAR_SERVER_PATH=1", reviewNoun: "Calendar CalDAV residual", prohibition: "never reads calendar event bodies or credentials from CalDAV stores.")
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
