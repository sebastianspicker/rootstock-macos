import Foundation
import RootstockCore

/// Lab Handoff clipboard depth review plan - documentation only.
public struct HandoffClipboardDepthPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.handoff_clipboard_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
static let documentationPlan = DocumentationPlanSpec(focusDefault: "Handoff clipboard depth", directory: "handoff_clipboard_depth-plan", filename: "handoff_clipboard_depth-plan.md", title: "Handoff clipboard depth plan", purpose: "Handoff / Universal Clipboard residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never reads Universal Clipboard contents or forges Handoff activity", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_HANDOFF_CLIPBOARD_DEPTH=1", reviewNoun: "Handoff clipboard depth", prohibition: "never reads Universal Clipboard contents or forges Handoff activity.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
