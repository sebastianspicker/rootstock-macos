import Foundation
import RootstockCore

/// Lab keychain path assessment plan - path inventory documentation only; never dumps keychain.
///
/// Research basis: PEASS / red-team keychain path inventory themes.
/// Safety and behavior: lab-root marker only; consent + dry-run; no security dump-keychain / secret reads.
public struct KeychainPathPlanLabAction: LabAction {
    public static let id = "lab.surface.keychain_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let techniqueNote = """
    Technique documentation (alpha - path assessment only): operators assess presence of \
    login.keychain-db, System.keychain, and related paths as high-value surfaces. Rootstock Red Lab \
    never runs `security dump-keychain`, never exports items, and never reads secret blobs; it only \
    documents path-assessment steps and may plant a lab-root marker for purple file events.
    """

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let markerURL = LabPaths.resolveLabRoot(params: request.parameters)
            .appendingPathComponent("keychain-path-plan", isDirectory: true)
            .appendingPathComponent("assessment.marker")
        return try execute(request: request, context: context, markerURL: markerURL)
    }

    private func execute(
        request: LabActionRequest,
        context: EvaluationContext,
        markerURL: URL
    ) throws -> ActionResult {
        let body = """
        # rootstock-red-lab keychain path plan marker
        # PATH ASSESSMENT ONLY - not a dump-keychain artifact
        ROOTSTOCK_RED_LAB_KEYCHAIN_PATH_PLAN=1
        NEVER_DUMP_KEYCHAIN=1
        HARMLESS=1
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: markerCopy(markerURL: markerURL)
            )
        )
    }

    private func markerCopy(markerURL: URL) -> FileMarkerCopy {
        FileMarkerCopy(
            plan: FileMarkerPlanCopy(
                message: """
            Dry-run keychain path plan: document path-existence assessment only; optional marker \
            at \(markerURL.path). Never dump-keychain or export items.
            """,
                steps: [
                "Inventory common keychain paths (existence / metadata only)",
                "Do not run security dump-keychain, find-generic-password, or item export",
                "Optional lab marker: \(markerURL.path)",
                Self.techniqueNote,
            ],
                cleanup: [
                "Delete \(markerURL.path) if planted",
                "Confirm no keychain DB files were read for secrets",
            ]
            ),
            apply: FileMarkerApplyCopy(
                dryRunMessage: "Dry-run: would write keychain path plan marker at \(markerURL.path)",
                successMessage: "Wrote keychain path plan marker at \(markerURL.path) (no keychain dump)",
                steps: [
            "Write keychain path-assessment marker under lab root only",
            "Refuse dump-keychain / secret extraction",
        ],
                cleanup: ["Delete \(markerURL.path)"]
            ),
            status: FileMarkerStatusCopy(
                presentMessage: "Keychain path plan marker present",
                absentMessage: "Keychain path plan marker absent",
                presentCleanup: ["Delete \(markerURL.path)"],
                absentCleanup: ["No artifact"]
            ),
            remove: FileMarkerRemoveCopy(
                dryRunMessage: { exists in "Dry-run: would delete keychain path plan marker (exists=\(exists))" },
                successMessage: { exists in "Removed keychain path plan marker (wasPresent=\(exists))" },
                steps: ["Delete \(markerURL.path)"],
                cleanup: ["Keychain DBs never dumped by this action"]
            )
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
