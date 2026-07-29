import Foundation
import RootstockCore

/// Lab Spotlight importer depth review plan - documentation only.
public struct SpotlightImporterDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.spotlight_importer_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Spotlight importer depth", directory: "spotlight_importer_depth-plan", filename: "spotlight_importer_depth-plan.md", title: "Spotlight importer depth plan", purpose: "Spotlight importer residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never installs malicious Spotlight importers or dumps mdworker index contents", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_SPOTLIGHT_IMPORTER_DEPTH=1", reviewNoun: "Spotlight importer depth", prohibition: "never installs malicious Spotlight importers or dumps mdworker index contents.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
