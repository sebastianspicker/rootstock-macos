import Foundation
import RootstockCore

/// Lab XPC Mach service depth review plan - documentation only.
public struct XpcMachServiceDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.xpc_mach_service_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "XPC Mach service depth", directory: "xpc_mach_service_depth-plan", filename: "xpc_mach_service_depth-plan.md", title: "XPC Mach service depth plan", purpose: "XPC Mach service residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never registers XPC services or injects into Mach ports", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE15_XPC_MACH_SERVICE_DEPTH=1", reviewNoun: "XPC Mach service depth", prohibition: "never registers XPC services or injects into Mach ports.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
