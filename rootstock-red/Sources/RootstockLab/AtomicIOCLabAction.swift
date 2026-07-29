import Foundation
import RootstockCore

/// Purple-team atomic IOC plant - reversible intentional detection artifact.
///
/// Research basis: Atomic Red Team / purple detection-pair ideas; dual-use “intentional IOC” catalogs.
/// Safety and behavior: consent-gated, dry-run default, structured plannedSteps + expected ESF notes;
/// no payload execution, no C2 beacon.
public struct AtomicIOCLabAction: LabAction {
    public static let id = "lab.purple.atomic_ioc"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let markerName = "rootstock-red-atomic.ioc"
    public static let esfExpectNote = """
    Expected detection surfaces (documentation only): file CREATE/WRITE under lab root; \
    optional OPEN by EDR scanners; no network CONNECT from this action. Pair with local \
    ESF/osquery rules looking for path contains 'rootstock-red-atomic'.
    """

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)

        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let technique = request.parameters["technique"] ?? "T1543.001"
        let markerURL = labRoot
            .appendingPathComponent("purple-ioc", isDirectory: true)
            .appendingPathComponent(Self.markerName)
        let body = """
        {
          "id": "com.rootstock.red.lab.atomic_ioc",
          "technique": "\(technique)",
          "purpose": "purple-team intentional IOC",
          "harmless": true,
          "createdBy": "rootstock-red-lab"
        }
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: Self.copy(markerURL: markerURL, technique: technique)
            )
        )
    }

    private static func copy(markerURL: URL, technique: String) -> FileMarkerCopy {
        FileMarkerCopy(
            plan: FileMarkerPlanCopy(message: "Dry-run atomic IOC plan: would plant detection marker at \(markerURL.path) tagged \(technique).", steps: ["Purple IOC path: \(markerURL.path)", "Document ATT&CK technique tag: \(technique)", Self.esfExpectNote, "Write JSON marker only - no process spawn, no network"], cleanup: ["Delete \(markerURL.path)", "Confirm SOC/test rules cleaned if they keyed on this path"]),
            apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write atomic IOC at \(markerURL.path)", successMessage: "Planted purple-team atomic IOC at \(markerURL.path) (technique=\(technique))", steps: ["Create purple-ioc directory", "Write intentional IOC JSON for technique \(technique)", "Do not execute payloads or open sockets"], cleanup: ["Delete \(markerURL.path)", Self.esfExpectNote]),
            status: FileMarkerStatusCopy(presentMessage: "Atomic IOC present at \(markerURL.path)", absentMessage: "Atomic IOC absent at \(markerURL.path)", presentCleanup: ["Delete \(markerURL.path) after detection validation"], absentCleanup: ["No IOC artifact"]),
            remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete atomic IOC (exists=\(exists))" }, successMessage: { exists in "Removed atomic IOC (wasPresent=\(exists))" }, cleanup: ["Confirm detection rules not left in noisy state"])
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
