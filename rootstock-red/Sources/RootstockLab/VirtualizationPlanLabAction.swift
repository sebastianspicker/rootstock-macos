import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct VirtualizationPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.virtualization_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    static let documentationPlan = DocumentationPlanSpec(focusDefault: "docker,colima,utm,virtualization.framework", directory: "virtualization-plan", filename: "virt-plan.md", title: "virtualization plan", purpose: "dual-use virt/container posture documentation", rules: ["document virtualization/container path inventory only under consent", "never start/stop Docker/VMs from this lab action", "never harvest image secrets or deploy nested C2", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_VIRTUALIZATION=1", reviewNoun: "virt/container dual-use observation", prohibition: "never starts/stops Docker/VMs or harvests image secrets")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
