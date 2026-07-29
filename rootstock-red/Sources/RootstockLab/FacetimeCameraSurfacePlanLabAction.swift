import Foundation
import RootstockCore

/// Lab FaceTime camera dual-use review plan - documentation only.
public struct FacetimeCameraSurfacePlanLabAction: LabAction {
    public static let id = "lab.surface.facetime_camera_surface_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "FaceTime camera dual-use", directory: "facetime_camera_surface-plan", filename: "facetime_camera_surface-plan.md", title: "FaceTime camera dual-use plan", purpose: "FaceTime / camera pipeline dual-use surface posture documentation", rules: ["document path/meta inventory only under consent", "never activates camera/mic or dumps FaceTime call history contents", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_FACETIME_CAMERA_SURFACE=1", reviewNoun: "FaceTime camera dual-use", prohibition: "never activates camera/mic or dumps FaceTime call history contents.")
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
