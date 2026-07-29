import Foundation
import RootstockCore

/// Lab Shortcuts iCloud sync review plan - documentation only.
public struct ShortcutsIcloudSyncPlanLabAction: LabAction {
    public static let id = "lab.surface.shortcuts_icloud_sync_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Shortcuts iCloud sync", directory: "shortcuts_icloud_sync-plan", filename: "shortcuts_icloud_sync-plan.md", title: "Shortcuts iCloud sync plan", purpose: "Shortcuts iCloud sync residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never executes Shortcuts or dumps iCloud-synced automation databases", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_SHORTCUTS_ICLOUD_SYNC=1", reviewNoun: "Shortcuts iCloud sync", prohibition: "never executes Shortcuts or dumps iCloud-synced automation databases.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
