import Foundation
import RootstockCore

/// Lab multi-stage LOOBin chain plan - documentation only (no chain execution).
public struct LOLMultistagePlanLabAction: LabAction {
    public static let id = "lab.surface.lol_multistage_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let chain = request.parameters["chain"] ?? "mdfind>osascript>launchctl"
        let markerURL = labRoot
            .appendingPathComponent("lol-multistage-plan", isDirectory: true)
            .appendingPathComponent("chain-plan.md")
        let body = """
        # rootstock-red-lab LOOBin multi-stage plan
        chain: \(chain)
        stages: discover → execute → persist
        esfExpected: [OPEN, EXEC]
        execute_chain: false
        ROOTSTOCK_RED_LAB_LOL_MULTISTAGE=1
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: Self.copy(markerURL: markerURL, chain: chain)
            )
        )
    }

    private static func copy(markerURL: URL, chain: String) -> FileMarkerCopy {
        FileMarkerCopy(plan: FileMarkerPlanCopy(message: "Dry-run LOL multi-stage plan for chain=\(chain): would write plan at \(markerURL.path). Does not execute the chain.", steps: ["Document dual-use stages: \(chain)", "Prefer quieter discovery bins before osascript", "Purple: expect ESF EXEC per stage if ever executed under separate ROE", "This action never spawns the chain binaries"], cleanup: ["Delete \(markerURL.path)"]), apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write LOL multi-stage plan at \(markerURL.path)", successMessage: "Wrote LOL multi-stage plan at \(markerURL.path)", steps: ["Write LOL multi-stage plan"], cleanup: ["Delete \(markerURL.path)"]), status: FileMarkerStatusCopy(presentMessage: "LOL multi-stage plan present", absentMessage: "LOL multi-stage plan absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]), remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete LOL multi-stage plan (exists=\(exists))" }, successMessage: { exists in "Removed LOL multi-stage plan (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["Chain was never executed by this action"]))
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
