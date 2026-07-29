import Foundation
import RootstockCore

/// Lab sudoers *surface plan* - documentation only; never rewrites sudoers.
///
/// Research basis: PEASS sudo assessment ideas; public Host_Alias/NOPASSWD misconfig themes.
/// Safety and behavior: plan/status only mutative path is optional lab marker file (not /etc/sudoers).
public struct SudoersPlanLabAction: LabAction {
    public static let id = "lab.surface.sudoers_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let techniqueNote = """
    Technique documentation (alpha - no sudoers mutation): privilege escalation via sudo \
    typically requires existing misconfiguration (NOPASSWD, weak Host_Alias, writable \
    sudoers.d). Rootstock Red Lab never runs CVE exploits or rewrites /etc/sudoers; it only \
    documents assessment steps and may plant a lab-root marker for purple file events.
    """

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let markerURL = labRoot
            .appendingPathComponent("sudoers-plan", isDirectory: true)
            .appendingPathComponent("assessment.marker")
        let body = """
        # rootstock-red-lab sudoers plan marker
        # NOT a sudoers fragment - do not copy to /etc/sudoers.d
        ROOTSTOCK_RED_LAB_SUDOERS_PLAN=1
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: Self.copy(markerURL: markerURL)
            )
        )
    }

    private static func copy(markerURL: URL) -> FileMarkerCopy {
        FileMarkerCopy(plan: FileMarkerPlanCopy(message: "Dry-run sudoers surface plan: document readable sudoers paths and NOPASSWD audit steps; optional marker at \(markerURL.path). Never rewrite system sudoers.", steps: ["Inventory /etc/sudoers and /etc/sudoers.d readability (assess vector)", "Do not execute sudo CVE PoCs or visudo writes", "Optional lab marker: \(markerURL.path)", Self.techniqueNote], cleanup: ["Delete \(markerURL.path) if planted", "Confirm /etc/sudoers* unchanged by this action"]), apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write sudoers plan marker at \(markerURL.path)", successMessage: "Wrote sudoers plan marker at \(markerURL.path) (not a system sudoers file)", steps: ["Write assessment marker under lab root only", "Refuse all writes under /etc/sudoers*"], cleanup: ["Delete \(markerURL.path)"]), status: FileMarkerStatusCopy(presentMessage: "Sudoers plan marker present", absentMessage: "Sudoers plan marker absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]), remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete sudoers plan marker (exists=\(exists))" }, successMessage: { exists in "Removed sudoers plan marker (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["/etc/sudoers* never modified"]))
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
