import Foundation
import RootstockCore

/// Lab PAM auth module surface review plan - documentation only.
public struct PamAuthModulePlanLabAction: LabAction {
    public static let id = "lab.surface.pam_auth_module_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "PAM auth module surface", directory: "pam_auth_module-plan", filename: "pam_auth_module-plan.md", title: "PAM auth module surface plan", purpose: "PAM authentication module residual surface posture documentation", rules: ["document path/meta inventory only under consent", "never installs PAM modules or modifies /etc/pam.d", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE14_PAM_AUTH_MODULE=1", reviewNoun: "PAM auth module surface", prohibition: "never installs PAM modules or modifies /etc/pam.d.")
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
