import Foundation
import RootstockCore

/// Lab TCC permission-graph probe plan - documentation + reversible marker only.
///
/// Research basis: SwiftBelt TCC path themes.
/// Safety and behavior: never forces TCC prompts; never dumps TCC.db; lab-root marker only.
public struct TCCGraphPlanLabAction: LabAction {
    public static let id = "lab.surface.tcc_graph_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let domains = request.parameters["domains"] ?? "FullDiskAccess,Automation,ScreenCapture"
        let markerURL = labRoot
            .appendingPathComponent("tcc-graph-plan", isDirectory: true)
            .appendingPathComponent("tcc-graph-plan.md")
        let body = """
        # rootstock-red-lab TCC permission graph plan
        domains: \(domains)
        rules:
        - non-prompting probes only
        - no TCC.db content dump
        - purple: expect ESF OPEN on protected roots if FDA exercised
        ROOTSTOCK_RED_LAB_TCC_GRAPH=1
        """
        return try LabMarkerLifecycle.runFileMarker(
            FileMarkerLifecycleRequest(
                actionId: Self.id,
                operation: request.operation,
                markerURL: markerURL,
                body: body,
                contextDryRun: context.dryRun,
                copy: Self.copy(markerURL: markerURL, domains: domains)
            )
        )
    }

    private static func copy(markerURL: URL, domains: String) -> FileMarkerCopy {
        FileMarkerCopy(plan: FileMarkerPlanCopy(message: "Dry-run TCC graph plan for domains [\(domains)]: would write plan at \(markerURL.path). No TCC prompts; no TCC.db dump.", steps: ["Document non-prompting probes for: \(domains)", "Pair with detect notes: OPEN of privacy-protected roots", "Write markdown plan under lab root only", "Never call APIs that force user TCC dialogs"], cleanup: ["Delete \(markerURL.path)"]), apply: FileMarkerApplyCopy(dryRunMessage: "Dry-run: would write TCC graph plan at \(markerURL.path)", successMessage: "Wrote TCC graph plan at \(markerURL.path)", steps: ["Write TCC graph plan"], cleanup: ["Delete \(markerURL.path)"]), status: FileMarkerStatusCopy(presentMessage: "TCC graph plan present", absentMessage: "TCC graph plan absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]), remove: FileMarkerRemoveCopy(dryRunMessage: { exists in "Dry-run: would delete TCC graph plan (exists=\(exists))" }, successMessage: { exists in "Removed TCC graph plan (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["TCC.db never written by this action"]))
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
