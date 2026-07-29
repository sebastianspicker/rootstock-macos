import Foundation
import RootstockCore

/// Purple xattr / quarantine detection-pair stub - technique + expected ESF OPEN/WRITE events.
///
/// Research basis: Atomic Red Team dual-use detection companions; quarantine/xattr monitoring themes.
/// Safety and behavior: reversible JSON under lab root; no process execution; consent + dry-run.
public struct XattrDetectPairLabAction: LabAction {
    public static let id = "lab.purple.xattr_detect_pair"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let markerName = "xattr-detect-pair.json"
    public static let defaultTechnique = "T1553.001"
    public static let defaultEvents = "OPEN,WRITE"

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let technique = request.parameters["technique"] ?? Self.defaultTechnique
        let events = request.parameters["esfEvents"] ?? Self.defaultEvents
        let eventList = LabPaths.jsonStringList(fromCSV: events)
        let markerURL = labRoot
            .appendingPathComponent("purple-xattr", isDirectory: true)
            .appendingPathComponent(Self.markerName)
        let body = """
        {
          "id": "com.rootstock.red.lab.xattr_detect_pair",
          "technique": "\(technique)",
          "esfExpected": [\(eventList)],
          "focus": "xattr/quarantine monitoring",
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
        FileMarkerCopy(plan: FileMarkerPlanCopy(message: "Dry-run xattr detect-pair plan: would write purple stub for \(technique) expecting [\(events)] (xattr/quarantine monitoring) at \(markerURL.path).", steps: ["Technique tag: \(technique)", "Expected ESF-style events for xattr/quarantine monitoring: \(events)", "Write purple detection-pair JSON: \(markerURL.path)", "No xattr mutations; pair with local ESF/osquery rules offline"], cleanup: ["Delete \(markerURL.path)", "Disable temporary detection rules if they keyed only on this lab path"]), apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write xattr detect-pair stub at \(markerURL.path)", successMessage: "Wrote xattr detect-pair stub at \(markerURL.path) (technique=\(technique))", steps: ["Create purple-xattr directory", "Write xattr/quarantine detection-pair JSON for \(technique)"], cleanup: ["Delete \(markerURL.path)"]), status: FileMarkerStatusCopy(presentMessage: "Xattr detect-pair stub present", absentMessage: "Xattr detect-pair stub absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]), remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete xattr detect-pair stub (exists=\(exists))" }, successMessage: { exists in "Removed xattr detect-pair stub (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No host ESF consumer modified"]))
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
