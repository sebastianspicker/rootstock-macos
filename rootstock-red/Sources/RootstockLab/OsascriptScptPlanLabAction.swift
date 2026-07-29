import Foundation
import RootstockCore

/// Lab OSA/scpt delivery review plan - documentation only.
public struct OsascriptScptPlanLabAction: LabAction {
    public static let id = "lab.surface.osascript_scpt_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    private static let documentationPlan = DocumentationPlanSpec(focusDefault: "OSA/scpt delivery", directory: "osascript_scpt-plan", filename: "osascript_scpt-plan.md", title: "OSA/scpt delivery plan", purpose: "Compiled AppleScript / OSA delivery residual posture documentation", rules: ["document path/meta inventory only under consent", "never compiles malicious .scpt payloads or executes third-party AppleScripts", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE12_OSASCRIPT_SCPT=1", reviewNoun: "OSA/scpt delivery", prohibition: "never compiles malicious .scpt payloads or executes third-party AppleScripts.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
