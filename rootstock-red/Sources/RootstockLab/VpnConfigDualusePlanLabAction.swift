import Foundation
import RootstockCore

/// Lab VPN config dual-use review plan - documentation only.
public struct VpnConfigDualusePlanLabAction: LabAction {
    public static let id = "lab.surface.vpn_config_dualuse_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "VPN config dual-use", directory: "vpn_config_dualuse-plan", filename: "vpn_config_dualuse-plan.md", title: "VPN config dual-use plan", purpose: "VPN configuration dual-use residual surface posture documentation", rules: ["document path/meta inventory only under consent", "never installs VPN profiles or rewrites network extension VPN configs", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE15_VPN_CONFIG_DUALUSE=1", reviewNoun: "VPN config dual-use", prohibition: "never installs VPN profiles or rewrites network extension VPN configs.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
