import Foundation
import RootstockCore

/// Lab mobileconfig / configuration-profile sideload risk plan - documentation only.
///
/// Research basis: profile payload risk inventory themes.
/// Safety and behavior: never installs real configuration profiles to the system.
public struct MobileconfigSideloadPlanLabAction: LabAction {
    public static let id = "lab.surface.mobileconfig_sideload_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let payloads = request.parameters["payloads"] ?? "com.apple.vpn.managed,com.apple.webcontent-filter"
        let markerURL = LabPaths.resolveLabRoot(params: request.parameters)
            .appendingPathComponent("mobileconfig-sideload-plan", isDirectory: true)
            .appendingPathComponent("profile-plan.json")
        return try execute(request: request, context: context, payloads: payloads, markerURL: markerURL)
    }

    private func execute(request: LabActionRequest, context: EvaluationContext, payloads: String, markerURL: URL) throws -> ActionResult {
        let payloadList = LabPaths.jsonStringList(fromCSV: payloads)
        let body = """
        {
          "id": "com.rootstock.red.lab.mobileconfig_sideload_plan",
          "payloadTypes": [\(payloadList)],
          "purpose": "configuration profile sideload risk plan",
          "harmless": true,
          "installProfiles": false,
          "neverInstallToSystem": true,
          "esfExpected": ["OPEN", "WRITE"]
        }
        """
        return try LabMarkerLifecycle.runFileMarker(FileMarkerLifecycleRequest(
            actionId: Self.id, operation: request.operation, markerURL: markerURL, body: body,
            contextDryRun: context.dryRun, copy: markerCopy(markerURL: markerURL, payloads: payloads)
        ))
    }

    private func markerCopy(markerURL: URL, payloads: String) -> FileMarkerCopy {
        FileMarkerCopy(
            plan: .init(message: "Dry-run mobileconfig sideload plan for payloads [\(payloads)]: would write plan at \(markerURL.path). Never installs real configuration profiles to the system.", steps: ["Document sideload risk review for payloads: \(payloads)", "Catalog detection opportunities for .mobileconfig delivery without install", "Write profile plan JSON under lab root only", "Never install configuration profiles via profiles(1) or System Settings"], cleanup: ["Delete \(markerURL.path)", "Confirm no system configuration profile was installed"]),
            apply: .init(dryRunMessage: "Dry-run: would write mobileconfig sideload plan at \(markerURL.path)", successMessage: "Wrote mobileconfig sideload plan at \(markerURL.path)", steps: ["Create mobileconfig-sideload-plan directory", "Write profile sideload risk plan JSON for \(payloads)"], cleanup: ["Delete \(markerURL.path)"]),
            status: .init(presentMessage: "Mobileconfig sideload plan present", absentMessage: "Mobileconfig sideload plan absent", presentCleanup: ["Delete \(markerURL.path)"], absentCleanup: ["No artifact"]),
            remove: .init(dryRunMessage: { exists in "Dry-run: would delete mobileconfig sideload plan (exists=\(exists))" }, successMessage: { exists in "Removed mobileconfig sideload plan (wasPresent=\(exists))" }, steps: ["Delete \(markerURL.path)"], cleanup: ["No real configuration profile was installed to the system"])
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
