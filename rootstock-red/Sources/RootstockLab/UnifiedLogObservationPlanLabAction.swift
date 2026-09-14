import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct UnifiedLogObservationPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.unified_log_observation_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    static let documentationPlan = DocumentationPlanSpec(focusDefault: "Unified log observation", directory: "unified_log-plan", filename: "unified_log-plan.md", title: "Unified log observation plan", purpose: "Unified log / logarchive observation depth posture documentation", rules: ["document path/meta inventory only under consent", "never dumps private unified-log message bodies or force-collects other users’ logarchives", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE12_UNIFIED_LOG=1", reviewNoun: "Unified log observation", prohibition: "never dumps private unified-log message bodies or force-collects other users’ logarchives")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
