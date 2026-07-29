import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct ThirdPartyTCCInheritancePlanLabAction: LabAction {
    public static let id = "lab.surface.third_party_tcc_inheritance_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    private static let documentationPlan = DocumentationPlanSpec(focusDefault: "electron,thick-client,interpreters", directory: "third-party-tcc-inheritance-plan", filename: "tcc-inheritance-plan.md", title: "third-party TCC inheritance plan", purpose: "thick-client / embedded-interpreter TCC inheritance posture documentation", rules: ["document TCC inheritance path inventory only under consent", "never forge TCC grants or modify TCC databases", "never strip entitlements or weaponize Electron inheritance", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_THIRD_PARTY_TCC_INHERITANCE=1", reviewNoun: "TCC inheritance", prohibition: "never forges TCC grants or modifies TCC databases")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
