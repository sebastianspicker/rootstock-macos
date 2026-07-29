import Foundation
import RootstockCore

/// Lab dylib surface planning - reversible markers only (no binary patching).
///
/// Unlike insert_dylib / load-command rewriting, alpha Rootstock Red never patches
/// Mach-O binaries. This action only:
/// - plan: documents a user-writable marker path for technique validation
/// - install (apply): writes an empty `.marker` file (not a real dylib)
/// - status: checks marker presence
/// - remove: deletes the marker
///
/// No keylog, no keychain dump, no C2, no real malicious dylib.
public struct DylibSurfaceLabAction: LabAction {
    public static let id = "lab.surface.dylib_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let techniqueNote = """
    Technique documentation (alpha - no binary mutation): real dylib hijack would involve \
    DYLD_* env, rpath abuse, or load-command injection (e.g. insert_dylib). Rootstock Red Lab \
    only plants a reversible empty marker under a user-controlled lab root so purple-team \
    detection can observe file create/delete without patching any application binary.
    """

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)

        let params = request.parameters
        let labRoot = Self.resolveLabRoot(params: params)
        let app = params["app"] ?? "generic"
        let markerURL = Self.markerURL(labRoot: labRoot, app: app)

        // Map CLI-oriented ops: plan stays plan; install == apply marker.
        switch request.operation {
        case .plan:
            return plan(markerURL: markerURL, labRoot: labRoot, app: app, dryRun: true)
        case .install:
            return try apply(
                markerURL: markerURL,
                labRoot: labRoot,
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
        markerURL: URL,
        labRoot: URL,
        app: String,
        dryRun: Bool
    ) -> ActionResult {
        let steps = [
            "Identify writable user lab root: \(labRoot.path)",
            "Marker path (empty placeholder, NOT a Mach-O dylib): \(markerURL.path)",
            "App slug for detection scenarios: \(app)",
            "Alpha: never patch binaries; never write real hijack dylibs",
            Self.techniqueNote,
        ]
        return ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Dry-run dylib surface plan for app=\(app): would plant reversible marker at \
            \(markerURL.path) under lab root \(labRoot.path). No binary patching; no real dylib.
            """,
            dryRun: dryRun,
            plannedSteps: steps,
            cleanupNotes: [
                "Delete marker: \(markerURL.path)",
                "Optionally remove empty parent dirs under \(labRoot.path)",
                "No binary reverse-patch needed (never modified)",
            ],
            artifacts: [markerURL.path]
        )
    }

    private func apply(
        markerURL: URL,
        labRoot: URL,
        app: String,
        dryRun: Bool
    ) throws -> ActionResult {
        let steps = [
            "Create lab root if needed: \(labRoot.path)",
            "Write empty marker file (not a dylib): \(markerURL.path)",
            "Do not touch application bundles or Mach-O load commands",
        ]
        let cleanup = [
            "Remove marker file \(markerURL.path)",
            "No binary cleanup required",
        ]

        if dryRun {
            return ActionResult(
                actionId: Self.id,
                success: true,
                message: """
                Dry-run: would write empty hijack-marker for app=\(app) at \(markerURL.path) \
                (NOT a real malicious dylib; no insert_dylib / no binary patch).
                """,
                dryRun: true,
                plannedSteps: steps,
                cleanupNotes: cleanup,
                artifacts: [markerURL.path]
            )
        }

        // Empty marker - not a dylib, not executable content.
        try LabMarkerLifecycle.writeMarker(at: markerURL, body: "")

        return ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Applied dylib-surface lab marker for app=\(app) at \(markerURL.path) \
            (empty placeholder only). Technique remains documented-only for real hijack; \
            binary patching is out of scope for alpha.
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
                ? "Dylib-surface marker present for app=\(app) at \(markerURL.path)"
                : "Dylib-surface marker absent for app=\(app) at \(markerURL.path)",
            dryRun: false,
            plannedSteps: ["Check marker exists at \(markerURL.path): \(exists)"],
            cleanupNotes: exists
                ? ["Delete \(markerURL.path) when validation complete"]
                : ["No marker artifact"],
            artifacts: exists ? [markerURL.path] : []
        )
    }

    private func remove(markerURL: URL, app: String, dryRun: Bool) throws -> ActionResult {
        let exists = LabMarkerLifecycle.markerExists(at: markerURL)
        let steps = [
            "Delete marker if present: \(markerURL.path)",
            "Leave application binaries untouched",
        ]

        if dryRun {
            return ActionResult(
                actionId: Self.id,
                success: true,
                message: """
                Dry-run: would delete dylib-surface marker for app=\(app) at \(markerURL.path) \
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
            Removed dylib-surface marker for app=\(app) at \(markerURL.path) \
            (wasPresent=\(exists)). No binary reverse needed.
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
            .appendingPathComponent("hijack-markers", isDirectory: true)
            .appendingPathComponent("\(safeApp).marker", isDirectory: false)
    }

    private static func sanitizePathComponent(_ raw: String) -> String {
        LabPaths.sanitizePathComponent(raw)
    }
}
