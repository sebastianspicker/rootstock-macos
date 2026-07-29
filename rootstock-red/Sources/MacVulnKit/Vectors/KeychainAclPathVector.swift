import Foundation
import RootstockCore

/// Path-to-impact: Keychain ACL path residual surface.
public struct KeychainAclPathVector: Check {
    public static let id = "rootstock.vector.data.keychain_acl_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.keychainAclPath
        let a = s?.keychainDbPaths.count ?? 0
        let b = s?.securityToolPaths.count ?? 0
        let c = s?.keychainSupportPaths.count ?? 0
        let surface = s?.keychainAclSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.keychain_acl_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "keychain_acl_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.keychainDbPaths + s.securityToolPaths + s.keychainSupportPaths, type: "keychain_acl_path_path", detail: "Keychain ACL path plane path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "keychain_acl_path_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps keychain items, passwords, or private keys."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Keychain ACL path plane with remote amplifier" : "Keychain ACL path residual surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1555.001", "T1555", "T1003"], remediation: [
                "Inventory and baseline Keychain ACL path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps keychain items, passwords, or private keys",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
