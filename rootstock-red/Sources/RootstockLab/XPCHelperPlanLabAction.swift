import Foundation
import RootstockCore

/// Lab XPC / privileged-helper *surface plan* - documentation + optional empty marker only.
///
/// Research basis: XPC helper abuse research themes; PEASS helper inventory.
/// Safety and behavior: never installs real privileged helpers into /Library; lab-root marker only;
/// plan documents detection and SIP constraints honestly.
public struct XPCHelperPlanLabAction: LabAction {
    public static let id = "lab.surface.xpc_helper_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let techniqueNote = """
    Technique documentation (alpha - no real helper install): abusing a weak Privileged Helper \
    Tool / XPC service typically requires an existing vulnerable helper or root to install one \
    under /Library/PrivilegedHelperTools. Rootstock Red Lab never writes system helper paths; \
    it only plans and optionally plants a reversible marker under a user lab root for purple \
    observation of file create/delete.
    """

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)

        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let helper = request.parameters["helper"] ?? "generic"
        let markerURL = Self.markerURL(labRoot: labRoot, helper: helper)
        let body = """
        # rootstock-red-lab xpc helper surface marker
        # helper=\(helper)
        # NOT a privileged helper binary; not loaded by launchd
        ROOTSTOCK_RED_LAB_XPC_MARKER=1
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: Self.copy(markerURL: markerURL, helper: helper)
            )
        )
    }

    private static func copy(markerURL: URL, helper: String) -> FileMarkerCopy {
        FileMarkerCopy(plan: FileMarkerPlanCopy(message: "Dry-run XPC helper surface plan for helper=\(helper): would plant marker at \(markerURL.path). No system PrivilegedHelperTools writes.", steps: ["Document XPC/helper surface for slug: \(helper)", "Real abuse path would target /Library/PrivilegedHelperTools - OUT OF SCOPE for writes", "Lab marker only: \(markerURL.path)", Self.techniqueNote, "SIP and root ownership normally block user helper installs"], cleanup: ["Delete \(markerURL.path)", "Confirm /Library/PrivilegedHelperTools was never modified by this action"]), apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write XPC helper marker for \(helper) at \(markerURL.path)", successMessage: "Wrote XPC helper surface marker for helper=\(helper) at \(markerURL.path) (lab marker only; no system helper installed).", steps: ["Write empty technique marker under lab root: \(markerURL.path)", "Do not copy binaries into /Library/PrivilegedHelperTools", "Do not bootstrap launchd jobs for fake helpers"], cleanup: ["Delete \(markerURL.path)", "No system helper reverse-install required"]), status: FileMarkerStatusCopy(presentMessage: "XPC helper marker present for \(helper) at \(markerURL.path)", absentMessage: "XPC helper marker absent for \(helper) at \(markerURL.path)", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No marker artifact"]), remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete XPC marker for \(helper) (exists=\(exists))" }, successMessage: { exists in "Removed XPC helper marker for \(helper) (wasPresent=\(exists))" }, cleanup: ["Confirm /Library/PrivilegedHelperTools untouched"]))
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }

    public static func markerURL(labRoot: URL, helper: String) -> URL {
        let safe = LabPaths.sanitizePathComponent(helper)
        return labRoot
            .appendingPathComponent("xpc-helper-markers", isDirectory: true)
            .appendingPathComponent("\(safe).marker")
    }
}
