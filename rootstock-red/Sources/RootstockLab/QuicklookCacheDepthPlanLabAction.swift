import Foundation
import RootstockCore

/// Lab QuickLook cache depth review plan - documentation only.
public struct QuicklookCacheDepthPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.quicklook_cache_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
static let documentationPlan = DocumentationPlanSpec(focusDefault: "QuickLook cache depth", directory: "quicklook_cache_depth-plan", filename: "quicklook_cache_depth-plan.md", title: "QuickLook cache depth plan", purpose: "QuickLook thumbnail cache residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never dumps QuickLook thumbnail bitmap contents as secret material", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE14_QUICKLOOK_CACHE_DEPTH=1", reviewNoun: "QuickLook cache depth", prohibition: "never dumps QuickLook thumbnail bitmap contents as secret material.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
