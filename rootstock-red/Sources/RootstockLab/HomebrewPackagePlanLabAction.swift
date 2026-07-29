import Foundation
import RootstockCore

/// Lab Homebrew package dual-use review plan - documentation only.
public struct HomebrewPackagePlanLabAction: LabAction {
    public static let id = "lab.surface.homebrew_package_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Homebrew package dual-use", directory: "homebrew_pkg-plan", filename: "homebrew_pkg-plan.md", title: "Homebrew package dual-use plan", purpose: "Homebrew / third-party package manager dual-use posture documentation", rules: ["document path/meta inventory only under consent", "never installs packages or modifies Homebrew formulae", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE13_HOMEBREW_PKG=1", reviewNoun: "Homebrew package dual-use", prohibition: "never installs packages or modifies Homebrew formulae.")
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
