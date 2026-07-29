import Foundation
import RootstockCore

/// Lab Emond legacy depth review plan - documentation only.
public struct EmondLegacyDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.emond_legacy_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Emond legacy depth", directory: "emond_legacy_depth-plan", filename: "emond_legacy_depth-plan.md", title: "Emond legacy depth plan", purpose: "Emond legacy rules residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never installs emond rules or enables the legacy event monitor daemon", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE15_EMOND_LEGACY_DEPTH=1", reviewNoun: "Emond legacy depth", prohibition: "never installs emond rules or enables the legacy event monitor daemon.")
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
