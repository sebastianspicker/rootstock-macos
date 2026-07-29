import Foundation
import RootstockCore

/// Documentation-only lab plan action.
public struct SSHAgentKeyPathPlanLabAction: LabAction {
    public static let id = "lab.surface.ssh_agent_key_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    private static let documentationPlan = DocumentationPlanSpec(focusDefault: "ssh-agent,authorized_keys,sshd", directory: "ssh-agent-key-path-plan", filename: "ssh-path-plan.md", title: "SSH agent/key path plan", purpose: "SSH-agent and key path lateral posture documentation", rules: ["document path/meta inventory only under consent", "never read private key material", "never connect to ssh-agent sockets or harvest credentials", "purple: validate expected telemetry under ROE only"], markerFlag: "ROOTSTOCK_RED_LAB_SSH_AGENT_KEY_PATH=1", reviewNoun: "SSH agent/key path lateral", prohibition: "never reads private keys or harvests credentials")
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try DocumentationPlanExecutor.run(actionId: Self.id, consent: Self.consent, spec: Self.documentationPlan, request: request, context: context)
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
