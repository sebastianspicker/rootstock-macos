import Foundation
import RootstockCore

/// Lab iCloud Drive path plane review plan - documentation only.
public struct IcloudDrivePathPlanLabAction: LabAction {
    public static let id = "lab.surface.icloud_drive_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "iCloud Drive path plane", directory: "icloud_drive_path-plan", filename: "icloud_drive_path-plan.md", title: "iCloud Drive path plane plan", purpose: "iCloud Drive / Mobile Documents path plane posture documentation", rules: ["document path/meta inventory only under consent", "never enumerates iCloud file contents or exfiltrates Mobile Documents", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE14_ICLOUD_DRIVE_PATH=1", reviewNoun: "iCloud Drive path plane", prohibition: "never enumerates iCloud file contents or exfiltrates Mobile Documents.")
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
