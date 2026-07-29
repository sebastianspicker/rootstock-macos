import Foundation
import RootstockCore

/// Lab Music library path review plan - documentation only.
public struct MusicLibraryPathPlanLabAction: LabAction {
    public static let id = "lab.surface.music_library_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Music library path", directory: "music_library_path-plan", filename: "music_library_path-plan.md", title: "Music library path plan", purpose: "Music / media library path residual posture documentation", rules: ["document path/meta inventory only under consent", "never exports Music library media or DRM material", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_MUSIC_LIBRARY_PATH=1", reviewNoun: "Music library path", prohibition: "never exports Music library media or DRM material.")
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
