import Foundation
import RootstockCore

/// Lab authorized-rights review plan - documentation + reversible marker only.
///
/// Research basis: auth.db rights inventory themes.
/// Safety and behavior: never edits /var/db/auth.db; lab-root marker only.
public struct AuthRightsPlanLabAction: LabAction {
    public static let id = "lab.surface.auth_rights_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let rights = request.parameters["rights"] ?? "system.preferences,system.install.software"
        let markerURL = labRoot
            .appendingPathComponent("auth-rights-plan", isDirectory: true)
            .appendingPathComponent("auth-plan.md")
        let body = """
        # rootstock-red-lab authorized rights plan
        rights: \(rights)
        purpose: documentation for auth rights review (not mutation)
        rules:
        - inventory and document only
        - never edit /var/db/auth.db
        - never run security authorizationdb write/remove
        - purple: expect OPEN of auth artifacts if read under separate ROE
        ROOTSTOCK_RED_LAB_AUTH_RIGHTS=1
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: Self.copy(markerURL: markerURL, rights: rights)
            )
        )
    }

    private static func copy(markerURL: URL, rights: String) -> FileMarkerCopy {
        FileMarkerCopy(
            plan: FileMarkerPlanCopy(message: "Dry-run authorized-rights plan for rights [\(rights)]: would write plan at \(markerURL.path). Never edits /var/db/auth.db.", steps: ["Document review procedure for rights: \(rights)", "Prefer offline / export-based inventory over live authdb mutation", "Write markdown plan under lab root only", "Never edit /var/db/auth.db or security authorizationdb write"], cleanup: ["Delete \(markerURL.path)", "Confirm auth.db was never modified"]),
            apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write auth rights plan at \(markerURL.path)", successMessage: "Wrote auth rights plan at \(markerURL.path)", steps: ["Write auth rights plan"], cleanup: ["Delete \(markerURL.path)"]),
            status: FileMarkerStatusCopy(presentMessage: "Auth rights plan present", absentMessage: "Auth rights plan absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]),
            remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete auth rights plan (exists=\(exists))" }, successMessage: { exists in "Removed auth rights plan (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["/var/db/auth.db was never edited by this action"])
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
