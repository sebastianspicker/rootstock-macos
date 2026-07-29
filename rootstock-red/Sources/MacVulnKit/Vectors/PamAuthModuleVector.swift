import Foundation
import RootstockCore

/// Path-to-impact: PAM authentication module residual surface.
public struct PamAuthModuleVector: Check {
    public static let id = "rootstock.vector.auth.pam_auth_module"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.pamAuthModule
        let a = s?.pamConfigPaths.count ?? 0
        let b = s?.pamModulePaths.count ?? 0
        let c = s?.authdSupportPaths.count ?? 0
        let surface = s?.pamSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.pam_auth_module"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "pam_auth_module_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.pamConfigPaths + s.pamModulePaths + s.authdSupportPaths, type: "pam_auth_module_path", detail: "PAM auth module surface path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "pam_auth_module_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs PAM modules or modifies /etc/pam.d."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "PAM auth module surface with remote amplifier" : "PAM authentication module residual surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1556", "T1543", "T1078"], remediation: [
                "Inventory and baseline PAM auth module surface paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs PAM modules or modifies /etc/pam.d",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
