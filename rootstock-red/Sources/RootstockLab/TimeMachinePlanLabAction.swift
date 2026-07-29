import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct TimeMachinePlanLabAction: LabAction {
    public static let id = "lab.surface.time_machine_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    private static let documentationPlan = DocumentationPlanSpec(focusDefault: "destination-info,latestbackup,mount-points", directory: "time-machine-plan", filename: "tm-plan.md", title: "Time Machine plan", purpose: "data-access surface documentation (not backup abuse)", rules: ["document destination/latest-backup metadata only under consent", "never silently mount foreign Time Machine volumes", "never restore from backups without explicit written ROE", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_TIME_MACHINE=1", reviewNoun: "data-access surface", prohibition: "never silently mounts foreign volumes or restores backups")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
