import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct ShortcutsAppIntentsPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.shortcuts_app_intents_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    static let documentationPlan = DocumentationPlanSpec(focusDefault: "Shortcuts / App Intents", directory: "shortcuts-app-intents-plan", filename: "shortcuts-plan.md", title: "Shortcuts / App Intents plan", purpose: "Shortcuts / App Intents posture documentation", rules: ["document path/meta inventory only under consent", "never runs shortcuts or forges App Intents", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_SHORTCUTS=1", reviewNoun: "Shortcuts / App Intents", prohibition: "never runs shortcuts or forges App Intents")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
