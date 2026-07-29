import Foundation
import RootstockCore

/// Lab DNS resolver dual-use review plan - documentation only.
public struct DnsResolverDualusePlanLabAction: LabAction {
    public static let id = "lab.surface.dns_resolver_dualuse_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "DNS resolver dual-use", directory: "dns_resolver_dualuse-plan", filename: "dns_resolver_dualuse-plan.md", title: "DNS resolver dual-use plan", purpose: "DNS resolver / mDNSResponder dual-use surface posture documentation", rules: ["document path/meta inventory only under consent", "never rewrites resolver config or poisons DNS caches", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE14_DNS_RESOLVER_DUALUSE=1", reviewNoun: "DNS resolver dual-use", prohibition: "never rewrites resolver config or poisons DNS caches.")
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
