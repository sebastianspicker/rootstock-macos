import Foundation
import RootstockCore

/// Shared plan / install / status / remove lifecycle for reversible lab file markers.
///
/// Technique-specific ids, messages, and marker bodies stay at call sites; only the
/// filesystem and `ActionResult` assembly lives here.
public enum LabMarkerLifecycle: Sendable {
    // MARK: - Filesystem primitives

    /// Create parent directories and write `body` atomically to `markerURL`.
    public static func writeMarker(at markerURL: URL, body: String) throws {
        try FileManager.default.createDirectory(
            at: markerURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data(body.utf8).write(to: markerURL, options: .atomic)
    }

    /// Whether a marker file currently exists.
    public static func markerExists(at markerURL: URL) -> Bool {
        FileManager.default.fileExists(atPath: markerURL.path)
    }

    /// Delete the marker if present. Returns whether it was present before removal.
    @discardableResult
    public static func removeMarker(at markerURL: URL) throws -> Bool {
        let exists = markerExists(at: markerURL)
        if exists {
            try FileManager.default.removeItem(at: markerURL)
        }
        return exists
    }

    // MARK: - Operation results

    /// Build a plan (always documentation-style) `ActionResult`.
    public static func plan(
        actionId: String,
        markerURL: URL,
        message: String,
        plannedSteps: [String],
        cleanupNotes: [String],
        dryRun: Bool = true
    ) -> ActionResult {
        ActionResult(
            actionId: actionId,
            success: true,
            message: message,
            dryRun: dryRun,
            plannedSteps: plannedSteps,
            cleanupNotes: cleanupNotes,
            artifacts: [markerURL.path]
        )
    }

    /// Install / apply a file marker, honoring dry-run.
    public static func apply(
        input: FileMarkerApplyInput,
        copy: FileMarkerApplyCopy
    ) throws -> ActionResult {
        if input.dryRun {
            return ActionResult(
                actionId: input.actionId,
                success: true,
                message: copy.dryRunMessage,
                dryRun: true,
                plannedSteps: copy.steps, cleanupNotes: copy.cleanup,
                artifacts: [input.markerURL.path]
            )
        }
        try writeMarker(at: input.markerURL, body: input.body)
        return ActionResult(
            actionId: input.actionId,
            success: true,
            message: copy.successMessage,
            dryRun: false,
            plannedSteps: copy.steps, cleanupNotes: copy.cleanup,
            artifacts: [input.markerURL.path]
        )
    }

    /// Status check for a single marker file.
    public static func status(
        actionId: String, markerURL: URL, presentMessage: String, absentMessage: String,
        plannedSteps: [String]? = nil, presentCleanup: [String]? = nil, absentCleanup: [String]? = nil
    ) -> ActionResult {
        let exists = markerExists(at: markerURL)
        let steps = plannedSteps ?? ["exists=\(exists)"]
        let cleanup = exists
            ? (presentCleanup ?? ["Delete \(markerURL.path)"]) : (absentCleanup ?? ["No artifact"])
        return ActionResult(
            actionId: actionId,
            success: true,
            message: exists ? presentMessage : absentMessage,
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: cleanup,
            artifacts: exists ? [markerURL.path] : []
        )
    }

    /// Remove a marker file, honoring dry-run.
    public static func remove(
        input: FileMarkerRemoveInput,
        copy: FileMarkerRemoveCopy
    ) throws -> ActionResult {
        let exists = markerExists(at: input.markerURL)
        let steps = copy.steps ?? ["Delete \(input.markerURL.path)"]
        if input.dryRun {
            return ActionResult(
                actionId: input.actionId,
                success: true,
                message: copy.dryRunMessage(exists),
                dryRun: true,
                plannedSteps: steps,
                cleanupNotes: copy.cleanup,
                artifacts: exists ? [input.markerURL.path] : []
            )
        }
        if exists {
            try FileManager.default.removeItem(at: input.markerURL)
        }
        return ActionResult(
            actionId: input.actionId,
            success: true,
            message: copy.successMessage(exists),
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: copy.cleanup,
            artifacts: exists ? [input.markerURL.path] : []
        )
    }

    /// Dispatch a full plan/install/status/remove lifecycle for a single file marker.
    public static func runFileMarker(
        _ request: FileMarkerLifecycleRequest
    ) throws -> ActionResult {
        switch request.operation {
        case .plan:
            return runFileMarkerPlan(actionId: request.actionId, markerURL: request.markerURL, copy: request.copy.plan)
        case .install:
            return try runFileMarkerApply(actionId: request.actionId, markerURL: request.markerURL, body: request.body, contextDryRun: request.contextDryRun, copy: request.copy.apply)
        case .status:
            return runFileMarkerStatus(actionId: request.actionId, markerURL: request.markerURL, copy: request.copy.status)
        case .remove:
            return try runFileMarkerRemove(actionId: request.actionId, markerURL: request.markerURL, contextDryRun: request.contextDryRun, copy: request.copy.remove)
        }
    }

    private static func runFileMarkerPlan(actionId: String, markerURL: URL, copy: FileMarkerPlanCopy) -> ActionResult {
        plan(actionId: actionId, markerURL: markerURL, message: copy.message, plannedSteps: copy.steps, cleanupNotes: copy.cleanup, dryRun: true)
    }

    private static func runFileMarkerApply(actionId: String, markerURL: URL, body: String, contextDryRun: Bool, copy: FileMarkerApplyCopy) throws -> ActionResult {
        try apply(input: FileMarkerApplyInput(actionId: actionId, markerURL: markerURL, body: body, dryRun: contextDryRun), copy: copy)
    }

    private static func runFileMarkerStatus(actionId: String, markerURL: URL, copy: FileMarkerStatusCopy) -> ActionResult {
        status(actionId: actionId, markerURL: markerURL, presentMessage: copy.presentMessage, absentMessage: copy.absentMessage, plannedSteps: copy.steps, presentCleanup: copy.presentCleanup, absentCleanup: copy.absentCleanup)
    }

    private static func runFileMarkerRemove(actionId: String, markerURL: URL, contextDryRun: Bool, copy: FileMarkerRemoveCopy) throws -> ActionResult {
        try remove(input: FileMarkerRemoveInput(actionId: actionId, markerURL: markerURL, dryRun: contextDryRun), copy: copy)
    }
}

/// Fixed-contract documentation plan used by simple reversible lab marker actions.
public struct DocumentationPlanSpec: Sendable {
    public let focusDefault: String
    public let directory: String
    public let filename: String
    public let title: String
    public let purpose: String
    public let rules: [String]
    public let markerFlag: String
    public let reviewNoun: String
    public let prohibition: String

}

public enum DocumentationPlanExecutor {
    public static func run(actionId: String, consent: ConsentPolicy, spec: DocumentationPlanSpec, request: LabActionRequest, context: EvaluationContext) throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? spec.focusDefault
        let markerURL = labRoot.appendingPathComponent(spec.directory, isDirectory: true).appendingPathComponent(spec.filename)
        let body = (["# rootstock-red-lab \(spec.title)", "focus: \(focus)", "purpose: \(spec.purpose)", "rules:"] + spec.rules.map { "- \($0)" } + [spec.markerFlag]).joined(separator: "\n")
        let copy = FileMarkerCopy(
            plan: FileMarkerPlanCopy(message: "Dry-run \(spec.title) for focus [\(focus)]: would write plan at \(markerURL.path). \(spec.prohibition)", steps: ["Document \(spec.reviewNoun) review for: \(focus)", "Note path/meta inventory without host mutation beyond lab root", "Write markdown plan under lab root only", "Purple: validate expected telemetry under ROE only"], cleanup: ["Delete \(markerURL.path)"]),
            apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write \(spec.title) at \(markerURL.path)", successMessage: "Wrote \(spec.title) at \(markerURL.path)", steps: ["Write \(spec.title)"], cleanup: ["Delete \(markerURL.path)"]),
            status: FileMarkerStatusCopy(presentMessage: "\(spec.title) present", absentMessage: "\(spec.title) absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]),
            remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete \(spec.title) (exists=\(exists))" }, successMessage: { exists in "Removed \(spec.title) (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No system mutations expected"])
        )
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: actionId,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: copy
            )
        )
    }
}


/// Technique-specific strings for a single file-marker lab action.
public struct FileMarkerCopy: Sendable {
    public let plan: FileMarkerPlanCopy
    public let apply: FileMarkerApplyCopy
    public let status: FileMarkerStatusCopy
    public let remove: FileMarkerRemoveCopy

    public init(
        plan: FileMarkerPlanCopy,
        apply: FileMarkerApplyCopy,
        status: FileMarkerStatusCopy,
        remove: FileMarkerRemoveCopy
    ) {
        self.plan = plan
        self.apply = apply
        self.status = status
        self.remove = remove
    }

}

public struct FileMarkerApplyInput: Sendable {
    public let actionId: String
    public let markerURL: URL
    public let body: String
    public let dryRun: Bool
}

public struct FileMarkerRemoveInput: Sendable {
    public let actionId: String
    public let markerURL: URL
    public let dryRun: Bool
}

public struct FileMarkerLifecycleRequest: Sendable {
    public let actionId: String
    public let operation: LabOperation
    public let markerURL: URL
    public let body: String
    public let contextDryRun: Bool
    public let copy: FileMarkerCopy
}

public struct FileMarkerPlanCopy: Sendable {
    public let message: String
    public let steps: [String]
    public let cleanup: [String]
    public init(message: String, steps: [String], cleanup: [String]) {
        self.message = message; self.steps = steps; self.cleanup = cleanup
    }
}

public struct FileMarkerApplyCopy: Sendable {
    public let dryRunMessage: String
    public let successMessage: String
    public let steps: [String]
    public let cleanup: [String]
    public init(dryRunMessage: String, successMessage: String, steps: [String], cleanup: [String]) {
        self.dryRunMessage = dryRunMessage; self.successMessage = successMessage; self.steps = steps; self.cleanup = cleanup
    }
}

public struct FileMarkerStatusCopy: Sendable {
    public let presentMessage: String
    public let absentMessage: String
    public let steps: [String]?
    public let presentCleanup: [String]?
    public let absentCleanup: [String]?
    public init(presentMessage: String, absentMessage: String, steps: [String]? = nil, presentCleanup: [String]? = nil, absentCleanup: [String]? = nil) {
        self.presentMessage = presentMessage; self.absentMessage = absentMessage; self.steps = steps; self.presentCleanup = presentCleanup; self.absentCleanup = absentCleanup
    }
}

public struct FileMarkerRemoveCopy: Sendable {
    public let dryRunMessage: @Sendable (Bool) -> String
    public let successMessage: @Sendable (Bool) -> String
    public let steps: [String]?
    public let cleanup: [String]
    public init(dryRunMessage: @escaping @Sendable (Bool) -> String, successMessage: @escaping @Sendable (Bool) -> String, steps: [String]? = nil, cleanup: [String]) {
        self.dryRunMessage = dryRunMessage; self.successMessage = successMessage; self.steps = steps; self.cleanup = cleanup
    }
}
