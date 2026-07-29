import Foundation
import RootstockCore

/// Lab DYLD_* environment injection surface plan - markers only, no process inject.
///
/// Research basis: InjectCheck / dylib hijack scanners + DYLD_INSERT_LIBRARIES technique notes.
/// Safety and behavior: no real DYLD injection into third-party apps; reversible env-file marker under
/// lab root; documents Hardened Runtime / library validation defeat conditions honestly.
public struct DyldEnvLabAction: LabAction {
    public static let id = "lab.surface.dyld_env"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let techniqueNote = """
    Technique documentation (alpha - no live process injection): DYLD_INSERT_LIBRARIES / \
    DYLD_LIBRARY_PATH can influence load order when Hardened Runtime is off or entitlements \
    allow dyld environment variables. Rootstock Red Lab never exports these into arbitrary \
    apps; it only plans and optionally writes a reversible env *marker file* under a lab root \
    for purple-team observation of file create/delete.
    """

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)

        let labRoot = Self.resolveLabRoot(params: request.parameters)
        let app = request.parameters["app"] ?? "generic"
        let markerURL = Self.markerURL(labRoot: labRoot, app: app)

        switch request.operation {
        case .plan:
            return plan(labRoot: labRoot, markerURL: markerURL, app: app, dryRun: true)
        case .install:
            return try apply(
                labRoot: labRoot,
                markerURL: markerURL,
                app: app,
                dryRun: context.dryRun
            )
        case .status:
            return status(markerURL: markerURL, app: app)
        case .remove:
            return try remove(markerURL: markerURL, app: app, dryRun: context.dryRun)
        }
    }

    // MARK: - Operations

    private func plan(
        labRoot: URL,
        markerURL: URL,
        app: String,
        dryRun: Bool
    ) -> ActionResult {
        let steps = [
            "Document DYLD surface for app slug: \(app)",
            "Preconditions for real abuse: HR off OR allow-dyld-environment-variables / disable-library-validation",
            "Lab marker path (env file, not injected): \(markerURL.path)",
            "Never export DYLD_INSERT_LIBRARIES into third-party processes from this action",
            Self.techniqueNote,
        ]
        return ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Dry-run DYLD env surface plan for app=\(app): would plant reversible env marker at \
            \(markerURL.path). No process injection; no real dylib insert.
            """,
            dryRun: dryRun,
            plannedSteps: steps,
            cleanupNotes: [
                "Delete \(markerURL.path)",
                "Confirm no DYLD_* exported in operator shell from this lab action",
            ],
            artifacts: [markerURL.path]
        )
    }

    private func apply(
        labRoot: URL,
        markerURL: URL,
        app: String,
        dryRun: Bool
    ) throws -> ActionResult {
        let steps = [
            "Create lab root if needed: \(labRoot.path)",
            "Write env marker file for app=\(app): \(markerURL.path)",
            "Contents document DYLD keys only - do not spawn target apps with those vars",
        ]
        let cleanup = [
            "Delete \(markerURL.path)",
            "No process un-inject required (never injected)",
        ]
        let body = """
        # rootstock-red-lab dyld env surface marker (NOT loaded automatically)
        # app=\(app)
        # Documented keys only - do not export into production apps from assess hosts:
        # DYLD_INSERT_LIBRARIES=
        # DYLD_LIBRARY_PATH=
        # DYLD_PRINT_LIBRARIES=1
        # Requires HR off or allow-dyld-environment-variables for impact on modern macOS.
        ROOTSTOCK_RED_LAB_DYLD_MARKER=1
        """

        if dryRun {
            return ActionResult(
                actionId: Self.id,
                success: true,
                message: "Dry-run: would write DYLD env marker for app=\(app) at \(markerURL.path)",
                dryRun: true,
                plannedSteps: steps,
                cleanupNotes: cleanup,
                artifacts: [markerURL.path]
            )
        }

        try LabMarkerLifecycle.writeMarker(at: markerURL, body: body)

        return ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Wrote DYLD env surface marker for app=\(app) at \(markerURL.path) \
            (documentation file only; no process injection).
            """,
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: cleanup,
            artifacts: [markerURL.path]
        )
    }

    private func status(markerURL: URL, app: String) -> ActionResult {
        let exists = LabMarkerLifecycle.markerExists(at: markerURL)
        return ActionResult(
            actionId: Self.id,
            success: true,
            message: exists
                ? "DYLD env marker present for app=\(app) at \(markerURL.path)"
                : "DYLD env marker absent for app=\(app) at \(markerURL.path)",
            dryRun: false,
            plannedSteps: ["Check marker exists: \(exists)"],
            cleanupNotes: exists
                ? ["Delete \(markerURL.path) when validation complete"]
                : ["No marker artifact"],
            artifacts: exists ? [markerURL.path] : []
        )
    }

    private func remove(markerURL: URL, app: String, dryRun: Bool) throws -> ActionResult {
        let exists = LabMarkerLifecycle.markerExists(at: markerURL)
        let steps = ["Delete env marker if present: \(markerURL.path)"]

        if dryRun {
            return ActionResult(
                actionId: Self.id,
                success: true,
                message: """
                Dry-run: would delete DYLD env marker for app=\(app) at \(markerURL.path) \
                (exists=\(exists)).
                """,
                dryRun: true,
                plannedSteps: steps,
                cleanupNotes: ["Confirm no leftover markers under lab root"],
                artifacts: exists ? [markerURL.path] : []
            )
        }

        if exists {
            try LabMarkerLifecycle.removeMarker(at: markerURL)
        }

        return ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Removed DYLD env marker for app=\(app) at \(markerURL.path) \
            (wasPresent=\(exists)). No process cleanup required.
            """,
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: ["Confirm no leftover markers under lab root"],
            artifacts: exists ? [markerURL.path] : []
        )
    }

    // MARK: - Paths

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }

    public static func markerURL(labRoot: URL, app: String) -> URL {
        let safeApp = sanitizePathComponent(app)
        return labRoot
            .appendingPathComponent("dyld-env-markers", isDirectory: true)
            .appendingPathComponent("\(safeApp).env", isDirectory: false)
    }

    private static func sanitizePathComponent(_ raw: String) -> String {
        LabPaths.sanitizePathComponent(raw)
    }
}
