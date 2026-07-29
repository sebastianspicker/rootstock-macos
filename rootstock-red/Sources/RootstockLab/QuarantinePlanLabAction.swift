import Foundation
import RootstockCore

/// Lab quarantine *technique plan* - documents com.apple.quarantine surface; never strips xattrs.
///
/// Research basis: PEASS / red-team download-quarantine assessment themes.
/// Safety and behavior: lab-root marker only; consent + dry-run; never mutates third-party app quarantine.
public struct QuarantinePlanLabAction: LabAction {
    public static let id = "lab.surface.quarantine_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let techniqueNote = """
    Technique documentation (alpha - no xattr strip): adversaries sometimes clear \
    com.apple.quarantine to reduce Gatekeeper prompts on downloaded binaries. Rootstock Red Lab \
    NEVER strips quarantine from third-party apps and NEVER writes outside the lab root; it only \
    documents the technique and plants a reversible marker under labRoot for purple observation.
    """

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let markerURL = labRoot
            .appendingPathComponent("quarantine-plan", isDirectory: true)
            .appendingPathComponent("marker.txt")
        let body = """
        # rootstock-red-lab quarantine plan marker
        # Technique: com.apple.quarantine (ATT&CK T1553.001)
        # NOT an xattr clear script - do not copy to production hosts
        ROOTSTOCK_RED_LAB_QUARANTINE_PLAN=1
        HARMLESS=1
        NEVER_STRIP_THIRD_PARTY_QUARANTINE=1
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
        FileMarkerCopy(plan: FileMarkerPlanCopy(message: "Dry-run quarantine plan: document com.apple.quarantine assessment steps; optional marker at \(markerURL.path). Never strip quarantine from third-party apps.", steps: ["Document com.apple.quarantine xattr assessment technique (T1553.001)", "Do not run xattr -d com.apple.quarantine on system or third-party paths", "Optional lab marker only: \(markerURL.path)", Self.techniqueNote], cleanup: ["Delete \(markerURL.path) if planted", "Confirm no third-party app quarantine xattrs were modified"]), apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write quarantine plan marker at \(markerURL.path)", successMessage: "Wrote quarantine plan marker at \(markerURL.path) (no xattr mutations)", steps: ["Write quarantine technique marker under lab root only", "Refuse all xattr strip / quarantine clear outside lab root"], cleanup: ["Delete \(markerURL.path)", "No system quarantine revert required (never stripped)"]), status: FileMarkerStatusCopy(presentMessage: "Quarantine plan marker present", absentMessage: "Quarantine plan marker absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]), remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete quarantine plan marker (exists=\(exists))" }, successMessage: { exists in "Removed quarantine plan marker (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No third-party quarantine xattrs were modified by this action"]))
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
