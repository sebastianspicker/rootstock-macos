import Foundation
import RootstockCore

/// Lab AirPlay receiver dual-use review plan - documentation only.
public struct AirplayReceiverSurfacePlanLabAction: LabAction {
    public static let id = "lab.surface.airplay_receiver_surface_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "AirPlay receiver dual-use", directory: "airplay_receiver_surface-plan", filename: "airplay_receiver_surface-plan.md", title: "AirPlay receiver dual-use plan", purpose: "AirPlay receiver dual-use residual posture documentation", rules: ["document path/meta inventory only under consent", "never enables AirPlay Receiver or spoofs AirPlay targets", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_AIRPLAY_RECEIVER_SURFACE=1", reviewNoun: "AirPlay receiver dual-use", prohibition: "never enables AirPlay Receiver or spoofs AirPlay targets.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(
            actionId: Self.id,
            consent: Self.consent,
            spec: Self.documentationPlan,
            request: request,
            context: context
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
