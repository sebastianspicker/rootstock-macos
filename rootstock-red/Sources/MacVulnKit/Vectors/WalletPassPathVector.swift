import Foundation
import RootstockCore

/// Path-to-impact: Wallet / pass residual path plane.
public struct WalletPassPathVector: Check {
    public static let id = "rootstock.vector.data.wallet_pass_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.walletPassPath
        let a = s?.walletAppPaths.count ?? 0
        let b = s?.passesStorePaths.count ?? 0
        let c = s?.passdPaths.count ?? 0
        let surface = s?.walletSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.wallet_pass_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "wallet_pass_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.walletAppPaths + s.passesStorePaths + s.passdPaths, type: "wallet_pass_path_path", detail: "Wallet pass path path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "wallet_pass_path_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps pass contents, payment tokens, or card data."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Wallet pass path with remote amplifier" : "Wallet / pass residual path plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1555", "T1083"], remediation: [
                "Inventory and baseline Wallet pass path paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps pass contents, payment tokens, or card data",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
