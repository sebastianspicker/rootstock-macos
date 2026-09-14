import Foundation
import RootstockCore

/// Lab MDM profile parse depth review plan - documentation only.
public struct MDMProfileParsePlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.mdm_profile_parse_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    static let documentationPlan = DocumentationPlanSpec(
        focusDefault: "MDM profile parse depth",
        directory: "mdm-profile-parse-plan",
        filename: "mdm-profile-parse-plan.md",
        title: "MDM profile parse depth plan",
        purpose: "MDM profile parse depth posture documentation",
        rules: ["document shallow PayloadType inventory only under consent", "never dump passwords, certificates, or shared secrets from profiles", "never install or forge configuration profiles", "purple: expect OPEN/READ of .mobileconfig if parse observed under ROE"],
        markerFlag: "ROOTSTOCK_RED_LAB_MDM_PROFILE_PARSE=1",
        reviewNoun: "MDM profile parse depth",
        prohibition: "never installs profiles or dumps secret payload values."
    )

    public init() {}


    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
