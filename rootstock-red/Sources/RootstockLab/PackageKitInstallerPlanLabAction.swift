import Foundation
import RootstockCore

/// Lab PackageKit installer design review plan - documentation only.
public struct PackageKitInstallerPlanLabAction: LabAction {
    public static let id = "lab.surface.packagekit_installer_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    private static let documentationPlan = DocumentationPlanSpec(focusDefault: "package_script_service,installd,receipts,InstallerSandboxes", directory: "packagekit-installer-plan", filename: "packagekit-plan.md", title: "PackageKit installer design plan", purpose: "PackageKit installer design posture documentation", rules: ["document package_script_service / installd / receipt path inventory only under consent", "never build malicious packages or invoke installd", "never weaponize InstallerSandboxes or preinstall/postinstall scripts", "purple: expect EXEC/WRITE of package services if install observed under ROE"], markerFlag: "ROOTSTOCK_RED_LAB_PACKAGEKIT_INSTALLER=1", reviewNoun: "PackageKit installer design", prohibition: "Never builds pkgs or invokes installd.")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
