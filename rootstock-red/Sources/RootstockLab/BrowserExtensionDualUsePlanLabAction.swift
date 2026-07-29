import Foundation
import RootstockCore

/// Lab Browser extension dual-use review plan - documentation only.
public struct BrowserExtensionDualUsePlanLabAction: LabAction {
    public static let id = "lab.surface.browser_extension_dualuse_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Browser extension dual-use"
        let markerURL = labRoot
            .appendingPathComponent("browser-extension-dualuse-plan", isDirectory: true)
            .appendingPathComponent("browser-extension-plan.md")
        let body = """
        # rootstock-red-lab Browser extension dual-use plan
        focus: \(focus)
        purpose: Browser extension dual-use posture documentation
        rules:
        - document path/meta inventory only under consent
        - never dumps extension secrets or cookies
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_BROWSER_EXT=1
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
            plan: FileMarkerPlanCopy(message: "Dry-run Browser extension dual-use plan for focus [\(focus)]: would write plan at             \(markerURL.path). never dumps extension secrets or cookies.\n", steps: ["Document Browser extension dual-use review for: \(focus)", "Note path/meta inventory without host mutation beyond lab root", "Write markdown plan under lab root only", "Purple: validate expected telemetry under ROE only"], cleanup: ["Delete \(markerURL.path)"]),
            apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write Browser extension dual-use plan at \(markerURL.path)", successMessage: "Wrote Browser extension dual-use plan at \(markerURL.path)", steps: ["Write Browser extension dual-use plan"], cleanup: ["Delete \(markerURL.path)"]),
            status: FileMarkerStatusCopy(presentMessage: "Browser extension dual-use plan present", absentMessage: "Browser extension dual-use plan absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]),
            remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete Browser extension dual-use plan (exists=\(exists))" }, successMessage: { exists in "Removed Browser extension dual-use plan (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No system mutations expected"])
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
