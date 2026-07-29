import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct LaunchdOverrideDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.launchd_override_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Launchd override depth", directory: "launchd-override-depth-plan", filename: "launchd-override-plan.md", title: "Launchd override depth plan", purpose: "Launchd override depth posture documentation", rules: ["document path/meta inventory only under consent", "never writes disabled.plist or unloads security products", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_LAUNCHD_OVERRIDE=1", reviewNoun: "Launchd override depth", prohibition: "never writes disabled.plist or unloads security products")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
