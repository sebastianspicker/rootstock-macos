import Foundation
import RootstockCore

/// Lab Remote Apple Events / EPPC review plan - documentation only.
public struct RemoteAppleEventsPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.remote_apple_events_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    static let documentationPlan = DocumentationPlanSpec(focusDefault: "remote-ae,eppc,ard", directory: "remote-apple-events-plan", filename: "rae-plan.md", title: "Remote Apple Events plan", purpose: "RAE/EPPC lateral posture documentation", rules: ["document Sharing/Remote Management path inventory only under consent", "never enable Remote Apple Events", "never send remote AppleEvents or craft EPPC lateral malware", "purple: expect OPEN of RemoteManagement prefs if inspected under ROE"], markerFlag: "ROOTSTOCK_RED_LAB_REMOTE_APPLE_EVENTS=1", reviewNoun: "remote automation lateral", prohibition: "Never enables RAE or sends AppleEvents.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
