import Foundation
import RootstockCore

/// Lab Finder Sync dual-use review plan - documentation only.
public struct FinderSyncExtensionPlanLabAction: LabAction {
    public static let id = "lab.surface.finder_sync_extension_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Finder Sync dual-use", directory: "finder_sync_extension-plan", filename: "finder_sync_extension-plan.md", title: "Finder Sync dual-use plan", purpose: "Finder Sync extension dual-use surface posture documentation", rules: ["document path/meta inventory only under consent", "never installs Finder Sync extensions or rewrites Finder preferences for abuse", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_FINDER_SYNC_EXTENSION=1", reviewNoun: "Finder Sync dual-use", prohibition: "never installs Finder Sync extensions or rewrites Finder preferences for abuse.")
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
