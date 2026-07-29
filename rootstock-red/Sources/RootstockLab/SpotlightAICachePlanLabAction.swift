import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct SpotlightAICachePlanLabAction: LabAction {
    public static let id = "lab.surface.spotlight_ai_cache_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    private static let documentationPlan = DocumentationPlanSpec(focusDefault: "spotlight,mdworker,ai-cache", directory: "spotlight-ai-cache-plan", filename: "spotlight-plan.md", title: "Spotlight/AI-cache plan", purpose: "index/cache data-access posture documentation", rules: ["document path/meta inventory only under consent", "never dump .Spotlight-V100 or AI model/cache contents", "never weaponize Sploitlight-class index access", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_SPOTLIGHT_AI_CACHE=1", reviewNoun: "index/cache data-access", prohibition: "never dumps index or AI cache contents")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
