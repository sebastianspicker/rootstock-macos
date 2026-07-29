import Foundation
import RootstockCore

/// Lab Network share mount review plan - documentation only.
public struct NetworkShareMountPlanLabAction: LabAction {
    public static let id = "lab.surface.network_share_mount_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    private static let documentationPlan = DocumentationPlanSpec(
        focusDefault: "Network share mount",
        directory: "network_share-plan",
        filename: "network_share-plan.md",
        title: "Network share mount plan",
        purpose: "Network share / SMB mount dual-use lateral posture documentation",
        rules: ["document path/meta inventory only under consent", "never mounts attacker shares or writes credentials to NetAuth", "purple: validate expected telemetry under ROE only"],
        markerFlag: "ROOTSTOCK_RED_LAB_WAVE12_NETWORK_SHARE=1",
        reviewNoun: "Network share mount",
        prohibition: "never mounts attacker shares or writes credentials to NetAuth."
    )

    public init() {}

    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(
            actionId: Self.id,
            consent: Self.consent,
            spec: Self.documentationPlan,
            request: request,
            context: context
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
