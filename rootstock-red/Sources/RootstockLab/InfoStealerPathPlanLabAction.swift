import Foundation
import RootstockCore

/// Lab Info-stealer path plane review plan - documentation only.
public struct InfoStealerPathPlanLabAction: LabAction {
    public static let id = "lab.surface.infostealer_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let root = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "browser,mail,messages,vaults,wallets"
        return try execute(request: request, context: context, root: root, focus: focus)
    }

    private func execute(request: LabActionRequest, context: EvaluationContext, root: URL, focus: String) throws -> ActionResult {
        let markerURL = root.appendingPathComponent("infostealer-path-plan", isDirectory: true)
            .appendingPathComponent("infostealer-path-plan.md")
        let body = "# rootstock-red-lab Info-stealer path plane plan\nfocus: \(focus)\npurpose: Info-stealer path plane posture documentation\nrules:\n- document multi-app collection path inventory only under consent\n- never dump cookies, passwords, keychain items, or wallet material\n- never harvest Messages/Mail contents\n- purple: expect OPEN/READ of high-value app data stores if inspected under ROE\nROOTSTOCK_RED_LAB_INFOSTEALER_PATH=1\n"
        return try LabMarkerLifecycle.runFileMarker(FileMarkerLifecycleRequest(
            actionId: Self.id, operation: request.operation, markerURL: markerURL, body: body,
            contextDryRun: context.dryRun, copy: markerCopy(markerURL: markerURL, focus: focus)
        ))
    }

    private func markerCopy(markerURL: URL, focus: String) -> FileMarkerCopy {
        FileMarkerCopy(
            plan: .init(message: "Dry-run Info-stealer path plane plan for focus [\(focus)]: would write plan at \(markerURL.path). Never dumps secrets or stealer payloads.", steps: ["Document Info-stealer path plane review for: \(focus)", "Note path/meta inventory without host mutation beyond lab root", "Write markdown plan under lab root only", "Purple: validate expected telemetry under ROE only"], cleanup: ["Delete \(markerURL.path)"]),
            apply: .init(dryRunMessage: "Dry-run: would write Info-stealer path plane plan at \(markerURL.path)", successMessage: "Wrote Info-stealer path plane plan at \(markerURL.path)", steps: ["Write Info-stealer path plane plan"], cleanup: ["Delete \(markerURL.path)"]),
            status: .init(presentMessage: "Info-stealer path plane plan present", absentMessage: "Info-stealer path plane plan absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]),
            remove: .init(dryRunMessage: { exists in "Dry-run: would delete Info-stealer path plane plan (exists=\(exists))" }, successMessage: { exists in "Removed Info-stealer path plane plan (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No secret harvest expected"])
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
