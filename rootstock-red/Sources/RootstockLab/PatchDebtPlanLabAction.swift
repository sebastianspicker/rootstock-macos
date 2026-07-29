import Foundation
import RootstockCore

/// Lab patch-debt documentation plan - suggester context only (no exploit download).
public struct PatchDebtPlanLabAction: LabAction {
    public static let id = "lab.surface.patch_debt_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let osVersion = request.parameters["osVersion"] ?? "unknown"
        let markerURL = labRoot
            .appendingPathComponent("patch-debt-plan", isDirectory: true)
            .appendingPathComponent("patch-debt-plan.md")
        let body = """
        # rootstock-red-lab patch-debt plan
        osVersion: \(osVersion)
        purpose: CVE class suggester documentation (not exploit pack)
        rules:
        - map ProductBuildVersion to Apple security content
        - confidence stays low until build-matched
        - no exploit download
        ROOTSTOCK_RED_LAB_PATCH_DEBT=1
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: Self.copy(markerURL: markerURL, osVersion: osVersion)
            )
        )
    }

    private static func copy(markerURL: URL, osVersion: String) -> FileMarkerCopy {
        FileMarkerCopy(plan: FileMarkerPlanCopy(message: "Dry-run patch-debt plan for os=\(osVersion): would write documentation at \(markerURL.path). No CVE exploit pack download.", steps: ["Record OS version context: \(osVersion)", "Map build to Apple security updates offline", "Write suggester notes under lab root only", "Never fetch or execute exploit PoCs"], cleanup: ["Delete \(markerURL.path)"]), apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write patch-debt plan at \(markerURL.path)", successMessage: "Wrote patch-debt plan at \(markerURL.path)", steps: ["Write patch-debt plan"], cleanup: ["Delete \(markerURL.path)"]), status: FileMarkerStatusCopy(presentMessage: "Patch-debt plan present", absentMessage: "Patch-debt plan absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]), remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete patch-debt plan (exists=\(exists))" }, successMessage: { exists in "Removed patch-debt plan (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No host updates applied by this action"]))
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
