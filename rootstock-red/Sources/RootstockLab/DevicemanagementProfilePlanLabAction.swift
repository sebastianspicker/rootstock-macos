import Foundation
import RootstockCore

/// Lab Device management profile review plan - documentation only.
public struct DevicemanagementProfilePlanLabAction: LabAction {
    public static let id = "lab.surface.devicemanagement_profile_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
private static let documentationPlan = DocumentationPlanSpec(focusDefault: "Device management profile", directory: "devicemanagement_profile-plan", filename: "devicemanagement_profile-plan.md", title: "Device management profile plan", purpose: "Device management profile residual depth posture documentation", rules: ["document path/meta inventory only under consent", "never installs configuration profiles or enrolls hosts in MDM", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_WAVE16_DEVICEMANAGEMENT_PROFILE=1", reviewNoun: "Device management profile", prohibition: "never installs configuration profiles or enrolls hosts in MDM.")
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
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
