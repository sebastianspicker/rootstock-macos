import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct SecurityMgmtPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.security_mgmt_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    private static let documentationPlan = DocumentationPlanSpec(focusDefault: "systemextensionsctl,helpers,unload-class", directory: "security-mgmt-plane-plan", filename: "mgmt-plane-plan.md", title: "security management-plane plan", purpose: "security-product management-plane / unload-class posture documentation", rules: ["document security-product management-plane path inventory only under consent", "never unload system extensions or stop EDR agents", "never send stop/unload XPC to security products", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_SECURITY_MGMT_PLANE=1", reviewNoun: "management-plane unload-class", prohibition: "never unloads system extensions or stops EDR agents")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
