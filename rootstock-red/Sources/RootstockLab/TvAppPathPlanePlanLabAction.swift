import Foundation
import RootstockCore

/// Lab TV.app path plane review plan - documentation only.
public struct TvAppPathPlanePlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.tv_app_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
static let documentationPlan = DocumentationPlanSpec(focusDefault: "TV.app path plane", directory: "tv_app_path_plane-plan", filename: "tv_app_path_plane-plan.md", title: "TV.app path plane plan", purpose: "TV.app residual path plane posture documentation", rules: ["document path/meta inventory only under consent", "never dumps TV.app media caches or account material", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_TV_APP_PATH_PLANE=1", reviewNoun: "TV.app path plane", prohibition: "never dumps TV.app media caches or account material.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
