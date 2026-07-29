import Foundation
import RootstockCore

/// Lab launch-constraint validation plan - documentation + marker only (no inject).
public struct LaunchConstraintPlanLabAction: LabAction {
    public static let id = "lab.surface.launch_constraint_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let target = request.parameters["target"] ?? "sample.app"
        let markerURL = LabPaths.resolveLabRoot(params: request.parameters)
            .appendingPathComponent("launch-constraint-plan", isDirectory: true)
            .appendingPathComponent("\(Self.sanitize(target)).plan.md")
        return try execute(request: request, context: context, target: target, markerURL: markerURL)
    }

    private func execute(
        request: LabActionRequest,
        context: EvaluationContext,
        target: String,
        markerURL: URL
    ) throws -> ActionResult {
        let body = """
        # rootstock-red-lab launch-constraint plan
        target: \(target)
        checks:
        - hardened runtime
        - library validation
        - get-task-allow
        - launch constraint artifacts
        esfExpected: [OPEN, EXEC]
        inject: forbidden
        ROOTSTOCK_RED_LAB_LAUNCH_CONSTRAINT=1
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: markerCopy(markerURL: markerURL, target: target)
            )
        )
    }

    private func markerCopy(markerURL: URL, target: String) -> FileMarkerCopy {
        FileMarkerCopy(
            plan: FileMarkerPlanCopy(
                message: """
            Dry-run launch-constraint plan for target=\(target): would write plan at \
            \(markerURL.path). No process injection.
            """,
                steps: [
                "Document codesign/HR/LV/get-task-allow review for \(target)",
                "Note launch-constraint artifacts if present",
                "Purple: ESF OPEN/EXEC expected for codesign probes",
                "Never perform runtime injection from lab",
            ],
                cleanup: ["Delete \(markerURL.path)"]
            ),
            apply: FileMarkerApplyCopy(
                dryRunMessage: "Dry-run: would write launch-constraint plan at \(markerURL.path)",
                successMessage: "Wrote launch-constraint plan at \(markerURL.path)",
                steps: ["Write launch-constraint plan"],
                cleanup: ["Delete \(markerURL.path)"]
            ),
            status: FileMarkerStatusCopy(
                presentMessage: "Launch-constraint plan present",
                absentMessage: "Launch-constraint plan absent",
                presentCleanup: ["Delete \(markerURL.path)"],
                absentCleanup: ["No artifact"]
            ),
            remove: FileMarkerRemoveCopy(
                dryRunMessage: { exists in "Dry-run: would delete launch-constraint plan (exists=\(exists))" },
                successMessage: { exists in "Removed launch-constraint plan (wasPresent=\(exists))" },
                steps: ["Delete \(markerURL.path)"],
                cleanup: ["No runtime inject was performed"]
            )
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }

    public static func sanitize(_ raw: String) -> String {
        LabPaths.sanitizePathComponent(raw)
    }
}
