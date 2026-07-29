import Foundation
import RootstockCore

/// Lab Dock persistence dual-use review plan - documentation only.
public struct DockPersistencePlanLabAction: LabAction {
    public static let id = "lab.surface.dock_persistence_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Dock persistence dual-use"
        let markerURL = labRoot
            .appendingPathComponent("dock_persist-plan", isDirectory: true)
            .appendingPathComponent("dock_persist-plan.md")
        let body = """
        # rootstock-red-lab Dock persistence dual-use plan
        focus: \(focus)
        purpose: Dock persistent apps / recent items dual-use posture documentation
        rules:
        - document path/meta inventory only under consent
        - never modifies Dock.plist or plants malicious Dock entries
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE12_DOCK_PERSIST=1
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: Self.copy(markerURL: markerURL, focus: focus)
            )
        )
    }

    private static func copy(markerURL: URL, focus: String) -> FileMarkerCopy {
        FileMarkerCopy(
            plan: FileMarkerPlanCopy(message: "Dry-run Dock persistence dual-use plan for focus [\(focus)]: would write plan at             \(markerURL.path). never modifies Dock.plist or plants malicious Dock entries.\n", steps: ["Document Dock persistence dual-use review for: \(focus)", "Note path/meta inventory without host mutation beyond lab root", "Write markdown plan under lab root only", "Purple: validate expected telemetry under ROE only"], cleanup: ["Delete \(markerURL.path)"]),
            apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write Dock persistence dual-use plan at \(markerURL.path)", successMessage: "Wrote Dock persistence dual-use plan at \(markerURL.path)", steps: ["Write Dock persistence dual-use plan"], cleanup: ["Delete \(markerURL.path)"]),
            status: FileMarkerStatusCopy(presentMessage: "Dock persistence dual-use plan present", absentMessage: "Dock persistence dual-use plan absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]),
            remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete Dock persistence dual-use plan (exists=\(exists))" }, successMessage: { exists in "Removed Dock persistence dual-use plan (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No system mutations expected"])
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
