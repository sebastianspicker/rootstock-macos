import Foundation
import RootstockCore

/// Lab Continuity / AirDrop review plan - documentation only.
public struct ContinuityAirDropPlanLabAction: LabAction {
    public static let id = "lab.surface.continuity_airdrop_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "airdrop,handoff,rapportd"
        let markerURL = labRoot
            .appendingPathComponent("continuity-airdrop-plan", isDirectory: true)
            .appendingPathComponent("continuity-plan.md")
        let body = """
        # rootstock-red-lab Continuity/AirDrop plan
        focus: \(focus)
        purpose: proximity transfer posture documentation
        rules:
        - document pref/framework inventory only under consent
        - never read Universal Clipboard contents
        - never force AirDrop transfers or craft proximity malware
        - purple: expect OPEN of sharingd prefs if inspected under ROE
        ROOTSTOCK_RED_LAB_CONTINUITY_AIRDROP=1
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
            plan: FileMarkerPlanCopy(message: "Dry-run Continuity/AirDrop plan for focus [\(focus)]: would write plan at \(markerURL.path). Never scrapes pasteboard or forces AirDrop sends.", steps: ["Document proximity transfer review for: \(focus)", "Note sharingd/rapportd path presence without pasteboard access", "Write markdown plan under lab root only", "Never build or send proximity malware"], cleanup: ["Delete \(markerURL.path)"]),
            apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write Continuity/AirDrop plan at \(markerURL.path)", successMessage: "Wrote Continuity/AirDrop plan at \(markerURL.path)", steps: ["Write Continuity/AirDrop plan"], cleanup: ["Delete \(markerURL.path)"]),
            status: FileMarkerStatusCopy(presentMessage: "Continuity/AirDrop plan present", absentMessage: "Continuity/AirDrop plan absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]),
            remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete Continuity/AirDrop plan (exists=\(exists))" }, successMessage: { exists in "Removed Continuity/AirDrop plan (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No AirDrop transfers were forced"])
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
