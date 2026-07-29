import Foundation
import RootstockCore

/// Lab periodic/maintenance technique marker - never writes system /etc/periodic.
///
/// Research basis: PEASS periodic privesc ideas; historical maintenance-script themes.
/// Safety and behavior: lab-root marker only; consent + dry-run; explicit no root plant.
public struct PeriodicMarkerLabAction: LabAction {
    public static let id = "lab.persist.periodic_marker"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let markerName = "rootstock-red-lab-periodic.marker"
    public static let techniqueNote = """
    Technique documentation: real abuse would place root-owned scripts under periodic \
    directories. Rootstock Red Lab never writes /etc/periodic or /usr/local/etc/periodic; \
    it only plants a reversible marker under a user lab root for purple observation.
    """

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let markerURL = labRoot
            .appendingPathComponent("periodic", isDirectory: true)
            .appendingPathComponent(Self.markerName)
        let body = """
        {"id":"com.rootstock.red.lab.periodic","technique":"T1053.003","harmless":true}
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: Self.copy(markerURL: markerURL)
            )
        )
    }

    private static func copy(markerURL: URL) -> FileMarkerCopy {
        FileMarkerCopy(plan: FileMarkerPlanCopy(message: "Dry-run periodic plan: would plant marker at \(markerURL.path). No /etc/periodic writes.", steps: ["Lab marker: \(markerURL.path)", "Do not write /etc/periodic or /usr/local/etc/periodic", Self.techniqueNote], cleanup: ["Delete \(markerURL.path)", "Confirm system periodic directories untouched"]), apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write periodic marker at \(markerURL.path)", successMessage: "Planted periodic technique marker at \(markerURL.path)", steps: ["Create lab periodic dir", "Write JSON technique marker (not a root script)"], cleanup: ["Delete \(markerURL.path)"]), status: FileMarkerStatusCopy(presentMessage: "Periodic marker present", absentMessage: "Periodic marker absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]), remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete periodic marker (exists=\(exists))" }, successMessage: { exists in "Removed periodic marker (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["System periodic dirs never modified"]))
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
