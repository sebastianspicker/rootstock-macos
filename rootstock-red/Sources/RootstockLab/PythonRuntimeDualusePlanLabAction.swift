import Foundation
import RootstockCore

/// Lab Python runtime dual-use review plan - documentation only.
public struct PythonRuntimeDualusePlanLabAction: LabAction {
    public static let id = "lab.surface.python_runtime_dualuse_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Python runtime dual-use", directory: "python_runtime_dualuse-plan", filename: "python_runtime_dualuse-plan.md", title: "Python runtime dual-use plan", purpose: "Python runtime dual-use residual surface posture documentation", rules: ["document path/meta inventory only under consent", "never executes third-party Python payloads or drops malicious site-packages", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE15_PYTHON_RUNTIME_DUALUSE=1", reviewNoun: "Python runtime dual-use", prohibition: "never executes third-party Python payloads or drops malicious site-packages.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
