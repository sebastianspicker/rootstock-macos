import Foundation
import RootstockCore

/// Lab Sandbox container depth review plan - documentation only.
public struct SandboxContainerDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.sandbox_container_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Sandbox container depth", directory: "sandbox_container_depth-plan", filename: "sandbox_container_depth-plan.md", title: "Sandbox container depth plan", purpose: "App sandbox container residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never breaks app sandbox or forges container entitlements", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE15_SANDBOX_CONTAINER_DEPTH=1", reviewNoun: "Sandbox container depth", prohibition: "never breaks app sandbox or forges container entitlements.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
