import Foundation
import RootstockCore

/// Lab Wallet pass path review plan - documentation only.
public struct WalletPassPathPlanLabAction: LabAction {
    public static let id = "lab.surface.wallet_pass_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Wallet pass path", directory: "wallet_pass_path-plan", filename: "wallet_pass_path-plan.md", title: "Wallet pass path plan", purpose: "Wallet / pass residual path plane posture documentation", rules: ["document path/meta inventory only under consent", "never dumps pass contents, payment tokens, or card data", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_WALLET_PASS_PATH=1", reviewNoun: "Wallet pass path", prohibition: "never dumps pass contents, payment tokens, or card data.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
