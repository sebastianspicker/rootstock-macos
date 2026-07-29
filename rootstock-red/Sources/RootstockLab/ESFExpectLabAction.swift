import Foundation
import RootstockCore

/// Purple ESF expectation stub - pairs a technique tag with expected Endpoint Security events.
///
/// Research basis: Atomic Red Team / dual-use detection companion ideas; ESF API talks.
/// Safety and behavior: reversible JSON under lab root; no process execution; consent + dry-run.
public struct ESFExpectLabAction: LabAction {
    public static let id = "lab.purple.esf_expect"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let markerName = "esf-expect.json"

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let technique = request.parameters["technique"] ?? "T1543.001"
        let events = request.parameters["esfEvents"] ?? "OPEN,WRITE,CREATE,EXEC"
        let eventList = LabPaths.jsonStringList(fromCSV: events)
        let markerURL = labRoot
            .appendingPathComponent("purple-esf", isDirectory: true)
            .appendingPathComponent(Self.markerName)
        let body = """
        {
          "id": "com.rootstock.red.lab.esf_expect",
          "technique": "\(technique)",
          "esfExpected": [\(eventList)],
          "purpose": "purple-team detection pair stub",
          "harmless": true
        }
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: Self.copy(markerURL: markerURL, technique: technique, events: events)
            )
        )
    }

    private static func copy(markerURL: URL, technique: String, events: String) -> FileMarkerCopy {
        FileMarkerCopy(
            plan: FileMarkerPlanCopy(message: "Dry-run ESF expect plan: would write detection-pair stub for \(technique) expecting [\(events)] at \(markerURL.path).", steps: ["Technique tag: \(technique)", "Expected ESF-style events: \(events)", "Write purple stub JSON: \(markerURL.path)", "No process spawn; pair with local ESF/osquery rules offline"], cleanup: ["Delete \(markerURL.path)", "Disable temporary detection rules if they keyed only on this lab path"]),
            apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write ESF expect stub at \(markerURL.path)", successMessage: "Wrote ESF expectation stub at \(markerURL.path) (technique=\(technique))", steps: ["Create purple-esf directory", "Write ESF expectation JSON for \(technique)"], cleanup: ["Delete \(markerURL.path)"]),
            status: FileMarkerStatusCopy(presentMessage: "ESF expect stub present", absentMessage: "ESF expect stub absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]),
            remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete ESF expect stub (exists=\(exists))" }, successMessage: { exists in "Removed ESF expect stub (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No host ESF consumer modified"])
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
