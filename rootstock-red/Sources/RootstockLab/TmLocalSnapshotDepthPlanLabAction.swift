import Foundation
import RootstockCore

/// Lab TM local snapshot depth review plan - documentation only.
public struct TmLocalSnapshotDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.tm_local_snapshot_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "TM local snapshot depth", directory: "tm_local_snapshot_depth-plan", filename: "tm_local_snapshot_depth-plan.md", title: "TM local snapshot depth plan", purpose: "Time Machine local snapshot residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never mounts snapshots for data theft or deletes backup catalogs", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE15_TM_LOCAL_SNAPSHOT_DEPTH=1", reviewNoun: "TM local snapshot depth", prohibition: "never mounts snapshots for data theft or deletes backup catalogs.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
