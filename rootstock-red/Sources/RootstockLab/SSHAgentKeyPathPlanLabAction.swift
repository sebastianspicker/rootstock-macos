import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct SSHAgentKeyPathPlanLabAction: DocumentationPlanLabAction {
    public static let id = "lab.surface.ssh_agent_key_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    static let documentationPlan = DocumentationPlanSpec(focusDefault: "ssh-agent,authorized_keys,sshd", directory: "ssh-agent-key-path-plan", filename: "ssh-path-plan.md", title: "SSH agent/key path plan", purpose: "SSH-agent and key path lateral posture documentation", rules: ["document path/meta inventory only under consent", "never read private key material", "never connect to ssh-agent sockets or harvest credentials", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_SSH_AGENT_KEY_PATH=1", reviewNoun: "SSH agent/key path lateral", prohibition: "never reads private keys or harvests credentials")
    public init() {}
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
