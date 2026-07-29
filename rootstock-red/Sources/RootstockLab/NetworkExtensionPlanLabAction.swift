import Foundation
import RootstockCore

/// Lab Network Extension / VPN / content-filter observation plan - documentation only.
///
/// Research basis: purple expectations for NE surfaces.
/// Safety and behavior: never modifies system NetworkExtension configuration; lab-root marker only.
public struct NetworkExtensionPlanLabAction: LabAction {
    public static let id = "lab.surface.network_extension_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let surfaces = request.parameters["surfaces"] ?? "VPN,content-filter,packet-tunnel"
        let markerURL = LabPaths.resolveLabRoot(params: request.parameters)
            .appendingPathComponent("network-extension-plan", isDirectory: true)
            .appendingPathComponent("ne-plan.json")
        return try execute(request: request, context: context, surfaces: surfaces, markerURL: markerURL)
    }

    private func execute(request: LabActionRequest, context: EvaluationContext, surfaces: String, markerURL: URL) throws -> ActionResult {
        let surfaceList = LabPaths.jsonStringList(fromCSV: surfaces)
        let body = """
        {
          "id": "com.rootstock.red.lab.network_extension_plan",
          "surfaces": [\(surfaceList)],
          "purpose": "purple-team NE/VPN/content-filter observation plan",
          "harmless": true,
          "neverModifySystemNEConfig": true,
          "esfExpected": ["OPEN", "EXEC", "NETWORK"]
        }
        """
        return try LabMarkerLifecycle.runFileMarker(FileMarkerLifecycleRequest(
            actionId: Self.id, operation: request.operation, markerURL: markerURL, body: body,
            contextDryRun: context.dryRun, copy: markerCopy(markerURL: markerURL, surfaces: surfaces)
        ))
    }

    private func markerCopy(markerURL: URL, surfaces: String) -> FileMarkerCopy {
        FileMarkerCopy(
            plan: .init(message: "Dry-run Network Extension plan for surfaces [\(surfaces)]: would write plan at \(markerURL.path). Never modifies system NetworkExtension configuration.", steps: ["Document purple observation expectations for: \(surfaces)", "Note NE/VPN/content-filter process and preference artifacts (read-only)", "Write NE plan JSON under lab root only", "Never modify system NetworkExtension config, preferences, or entitlements"], cleanup: ["Delete \(markerURL.path)", "Confirm no system NE/VPN configuration was modified"]),
            apply: .init(dryRunMessage: "Dry-run: would write Network Extension plan at \(markerURL.path)", successMessage: "Wrote Network Extension plan at \(markerURL.path)", steps: ["Create network-extension-plan directory", "Write NE observation plan JSON for \(surfaces)"], cleanup: ["Delete \(markerURL.path)"]),
            status: .init(presentMessage: "Network Extension plan present", absentMessage: "Network Extension plan absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]),
            remove: .init(dryRunMessage: { exists in "Dry-run: would delete Network Extension plan (exists=\(exists))" }, successMessage: { exists in "Removed Network Extension plan (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No system NetworkExtension configuration was modified"])
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
