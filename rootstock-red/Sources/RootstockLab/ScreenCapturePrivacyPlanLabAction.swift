import Foundation
import RootstockCore

/// Lab ScreenCapture privacy dual-use review plan - documentation only.
public struct ScreenCapturePrivacyPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.screencapture_privacy_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
static let documentationPlan = DocumentationPlanSpec(focusDefault: "ScreenCapture privacy dual-use", directory: "screencapture-plan", filename: "screencapture-plan.md", title: "ScreenCapture privacy dual-use plan", purpose: "ScreenCapture / screenshot privacy dual-use depth posture documentation", rules: ["document path/meta inventory only under consent", "never captures screens or dumps Screen Recording TCC rows", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE13_SCREENCAPTURE=1", reviewNoun: "ScreenCapture privacy dual-use", prohibition: "never captures screens or dumps Screen Recording TCC rows.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
