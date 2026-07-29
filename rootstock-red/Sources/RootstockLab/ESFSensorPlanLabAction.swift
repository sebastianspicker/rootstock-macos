import Foundation
import RootstockCore

/// Lab ESF sensor observation plan - documentation + reversible purple stub only.
///
/// Research basis: ESF event vocabulary; purple detection pairs.
/// Safety and behavior: never unloads ES clients; lab-root marker only; consent + dry-run default.
public struct ESFSensorPlanLabAction: LabAction {
    public static let id = "lab.surface.esf_sensor_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let markerURL = labRoot
            .appendingPathComponent("esf-sensor-plan", isDirectory: true)
            .appendingPathComponent("sensor-plan.json")
        let events = request.parameters["esfEvents"] ?? "OPEN,EXEC,WRITE"
        let eventList = LabPaths.jsonStringList(fromCSV: events)
        let body = """
        {
          "id": "com.rootstock.red.lab.esf_sensor_plan",
          "esfExpected": [\(eventList)],
          "purpose": "purple-team sensor observation plan",
          "harmless": true,
          "neverUnloadSensors": true
        }
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: Self.copy(markerURL: markerURL, events: events)
            )
        )
    }

    private static func copy(markerURL: URL, events: String) -> FileMarkerCopy {
        FileMarkerCopy(plan: FileMarkerPlanCopy(message: "Dry-run ESF sensor plan: would write observation stub expecting [\(events)] at \(markerURL.path). Does not unload Endpoint Security clients.", steps: ["Document expected ESF events: \(events)", "Write purple sensor plan JSON under lab root only", "Pair with offline osquery/ES rules - no live ES subscription from lab", "Never unload endpointsecurityd or third-party sensors"], cleanup: ["Delete \(markerURL.path)", "Confirm no system ES client configuration was modified"]), apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write ESF sensor plan at \(markerURL.path)", successMessage: "Wrote ESF sensor plan at \(markerURL.path)", steps: ["Create esf-sensor-plan directory", "Write sensor plan JSON for events \(events)"], cleanup: ["Delete \(markerURL.path)"]), status: FileMarkerStatusCopy(presentMessage: "ESF sensor plan present", absentMessage: "ESF sensor plan absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]), remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete ESF sensor plan (exists=\(exists))" }, successMessage: { exists in "Removed ESF sensor plan (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No ES client unload performed"]))
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
