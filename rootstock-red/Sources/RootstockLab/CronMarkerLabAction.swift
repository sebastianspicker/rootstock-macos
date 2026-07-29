import Foundation
import RootstockCore

/// Lab scheduled-task technique marker (user lab root only - not system crontab).
///
/// Research basis: PersistentJXA / PEASS cron & periodic technique ideas.
/// Safety and behavior: no `crontab` binary invocation, no root periodic writes; reversible marker
/// file under lab root with full lifecycle + BTM/OPSEC honesty about real cron noise.
public struct CronMarkerLabAction: LabAction {
    public static let id = "lab.persist.cron_marker"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let markerFileName = "rootstock-red-lab-cron.marker"
    public static let techniqueNote = """
    Technique documentation (alpha - no system crontab mutation): real user crontab or \
    /etc/periodic abuse would invoke crontab(1) or write root-owned periodic scripts. \
    Rootstock Red Lab only plants a reversible marker under a user lab root so purple-team \
    detection can observe scheduled-task intent artifacts without touching system schedulers.
    """

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)

        let labRoot = Self.resolveLabRoot(params: request.parameters)
        let markerURL = Self.markerURL(labRoot: labRoot)

        switch request.operation {
        case .plan:
            return plan(labRoot: labRoot, markerURL: markerURL, dryRun: true)
        case .install:
            return try apply(labRoot: labRoot, markerURL: markerURL, dryRun: context.dryRun)
        case .status:
            return status(markerURL: markerURL)
        case .remove:
            return try remove(markerURL: markerURL, dryRun: context.dryRun)
        }
    }

    // MARK: - Operations

    private func plan(labRoot: URL, markerURL: URL, dryRun: Bool) -> ActionResult {
        let steps = [
            "Lab root (user-controlled): \(labRoot.path)",
            "Marker path: \(markerURL.path)",
            "Write JSON technique marker (NOT a crontab line; NOT /etc/periodic)",
            Self.techniqueNote,
            "Do not call crontab(1) or write /var/at/tabs",
        ]
        return ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Dry-run cron technique plan: would plant scheduled-task marker at \(markerURL.path). \
            No system crontab changes.
            """,
            dryRun: dryRun,
            plannedSteps: steps,
            cleanupNotes: [
                "Delete \(markerURL.path)",
                "Confirm crontab -l was never modified by this lab action",
            ],
            artifacts: [markerURL.path]
        )
    }

    private func apply(labRoot: URL, markerURL: URL, dryRun: Bool) throws -> ActionResult {
        let steps = [
            "Create lab root if needed: \(labRoot.path)",
            "Write technique marker JSON: \(markerURL.path)",
            "Skip crontab(1) and system periodic directories",
        ]
        let cleanup = [
            "Delete \(markerURL.path)",
            "No crontab revert required (never modified)",
        ]
        let payload = """
        {
          "id": "com.rootstock.red.lab.cron_marker",
          "technique": "T1053.003",
          "note": "harmless scheduled-task technique marker; not loaded by cron",
          "createdBy": "rootstock-red-lab"
        }
        """

        if dryRun {
            return ActionResult(
                actionId: Self.id,
                success: true,
                message: "Dry-run: would write cron technique marker at \(markerURL.path)",
                dryRun: true,
                plannedSteps: steps,
                cleanupNotes: cleanup,
                artifacts: [markerURL.path]
            )
        }

        try LabMarkerLifecycle.writeMarker(at: markerURL, body: payload)

        return ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Planted scheduled-task technique marker at \(markerURL.path) \
            (not registered with cron; harmless JSON only).
            """,
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: cleanup,
            artifacts: [markerURL.path]
        )
    }

    private func status(markerURL: URL) -> ActionResult {
        LabMarkerLifecycle.status(
            actionId: Self.id,
            markerURL: markerURL,
            presentMessage: "Cron technique marker present at \(markerURL.path)",
            absentMessage: "Cron technique marker absent at \(markerURL.path)",
            presentCleanup: ["Delete \(markerURL.path) when validation complete"],
            absentCleanup: ["No marker artifact"]
        )
    }

    private func remove(markerURL: URL, dryRun: Bool) throws -> ActionResult {
        return try LabMarkerLifecycle.remove(
            input: FileMarkerRemoveInput(
                actionId: Self.id,
                markerURL: markerURL,
                dryRun: dryRun
            ),
            copy: FileMarkerRemoveCopy(
                dryRunMessage: { exists in "Dry-run: would delete cron marker at \(markerURL.path) (exists=\(exists))" },
                successMessage: { exists in "Removed cron technique marker at \(markerURL.path) (wasPresent=\(exists))" },
                steps: ["Delete marker if present: \(markerURL.path)"],
                cleanup: dryRun
                    ? ["Confirm no leftover markers under lab root"]
                    : ["Confirm crontab -l unchanged by this lab action"]
            )
        )
    }

    // MARK: - Paths

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params, subdirectory: "cron")
    }

    public static func markerURL(labRoot: URL) -> URL {
        labRoot.appendingPathComponent(markerFileName, isDirectory: false)
    }
}
