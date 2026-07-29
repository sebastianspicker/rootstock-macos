import Foundation
import RootstockCore

/// Lab Shell plugin manager dual-use review plan - documentation only.
public struct ShellPluginManagerPlanLabAction: LabAction {
    public static let id = "lab.surface.shell_plugin_manager_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Shell plugin manager dual-use", directory: "shell_plugin_manager-plan", filename: "shell_plugin_manager-plan.md", title: "Shell plugin manager dual-use plan", purpose: "Shell plugin manager dual-use residual posture documentation", rules: ["document path/meta inventory only under consent", "never installs oh-my-zsh plugins or rewrites shell init for persistence", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE15_SHELL_PLUGIN_MANAGER=1", reviewNoun: "Shell plugin manager dual-use", prohibition: "never installs oh-my-zsh plugins or rewrites shell init for persistence.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
