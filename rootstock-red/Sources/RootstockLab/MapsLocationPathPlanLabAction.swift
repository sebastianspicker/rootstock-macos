import Foundation
import RootstockCore

/// Lab Maps location residual review plan - documentation only.
public struct MapsLocationPathPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.maps_location_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
static let documentationPlan = DocumentationPlanSpec(focusDefault: "Maps location residual", directory: "maps_location_path-plan", filename: "maps_location_path-plan.md", title: "Maps location residual plan", purpose: "Maps / location services residual plane posture documentation", rules: ["document path/meta inventory only under consent", "never dumps location history or spoofs CoreLocation positions", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_MAPS_LOCATION_PATH=1", reviewNoun: "Maps location residual", prohibition: "never dumps location history or spoofs CoreLocation positions.")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
