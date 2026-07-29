import Foundation
import RootstockCore

/// Lab Keychain ACL path plane review plan - documentation only.
public struct KeychainAclPathPlanLabAction: LabAction {
    public static let id = "lab.surface.keychain_acl_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Keychain ACL path plane", directory: "keychain_acl_path-plan", filename: "keychain_acl_path-plan.md", title: "Keychain ACL path plane plan", purpose: "Keychain ACL path residual surface posture documentation", rules: ["document path/meta inventory only under consent", "never dumps keychain items, passwords, or private keys", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE15_KEYCHAIN_ACL_PATH=1", reviewNoun: "Keychain ACL path plane", prohibition: "never dumps keychain items, passwords, or private keys.")
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
