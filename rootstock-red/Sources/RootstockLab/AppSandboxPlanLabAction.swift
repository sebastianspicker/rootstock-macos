import Foundation
import RootstockCore

/// Lab app-sandbox / entitlement review plan - documentation + reversible marker only.
///
/// Research basis: entitlement review checklists.
/// Safety and behavior: never strips entitlements or injects processes; lab-root marker only.
public struct AppSandboxPlanLabAction: LabAction {
    public static let id = "lab.surface.app_sandbox_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "thick-clients,get-task-allow,hardened-runtime"
        let markerURL = labRoot
            .appendingPathComponent("app-sandbox-plan", isDirectory: true)
            .appendingPathComponent("sandbox-plan.md")
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: Self.markerBody(focus: focus),
                contextDryRun: context.dryRun,
                copy: Self.copy(markerURL: markerURL, focus: focus)
            )
        )
    }

    private static func markerBody(focus: String) -> String {
        """
        # rootstock-red-lab app-sandbox plan
        focus: \(focus)
        purpose: thick-client entitlement/sandbox posture documentation
        rules:
        - document sandbox/HR/get-task-allow class only under consent
        - never strip entitlements or disable sandbox
        - never inject processes or ship inject tooling
        - purple: expect OPEN of sampled .app bundles if codesign used under separate ROE
        ROOTSTOCK_RED_LAB_APP_SANDBOX=1
        """
    }

    private static func copy(markerURL: URL, focus: String) -> FileMarkerCopy {
        FileMarkerCopy(
            plan: FileMarkerPlanCopy(message: "Dry-run app-sandbox plan for focus [\(focus)]: would write plan at \(markerURL.path). Never strips entitlements or injects processes.", steps: ["Document entitlement/sandbox review for: \(focus)", "Note thick-client samples without mutating entitlements", "Write markdown plan under lab root only", "Purple: expect OPEN of app bundle paths if codesign inspected under ROE"], cleanup: ["Delete \(markerURL.path)", "Confirm no entitlement or codesign mutations"]),
            apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write app-sandbox plan at \(markerURL.path)", successMessage: "Wrote app-sandbox plan at \(markerURL.path)", steps: ["Write app-sandbox plan"], cleanup: ["Delete \(markerURL.path)"]),
            status: FileMarkerStatusCopy(presentMessage: "App-sandbox plan present", absentMessage: "App-sandbox plan absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]),
            remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete app-sandbox plan (exists=\(exists))" }, successMessage: { exists in "Removed app-sandbox plan (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No entitlements were modified"])
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
