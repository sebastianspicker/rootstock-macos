import Foundation
import RootstockCore

/// Lab File Provider domain review plan - documentation only.
public struct FileproviderDomainPlanLabAction: LabAction {
    public static let id = "lab.surface.fileprovider_domain_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "File Provider domain", directory: "fileprovider_domain-plan", filename: "fileprovider_domain-plan.md", title: "File Provider domain plan", purpose: "File Provider domain residual surface posture documentation", rules: ["document path/meta inventory only under consent", "never registers malicious File Provider domains or exfiltrates provider caches", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_FILEPROVIDER_DOMAIN=1", reviewNoun: "File Provider domain", prohibition: "never registers malicious File Provider domains or exfiltrates provider caches.")
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
