import Foundation
import RootstockCore

/// Lab Contacts path plane review plan - documentation only.
public struct ContactsPathPlanePlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.contacts_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
static let documentationPlan = DocumentationPlanSpec(focusDefault: "Contacts path plane", directory: "contacts_path_plane-plan", filename: "contacts_path_plane-plan.md", title: "Contacts path plane plan", purpose: "Contacts database path residual plane posture documentation", rules: ["document path/meta inventory only under consent", "never exports contact cards or dumps AddressBook database contents", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_CONTACTS_PATH_PLANE=1", reviewNoun: "Contacts path plane", prohibition: "never exports contact cards or dumps AddressBook database contents.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
