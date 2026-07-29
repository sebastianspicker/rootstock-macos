import Foundation
import RootstockCore

/// Path-to-impact: missing or thin security-product / EDR coverage with elevated host surface.
///
/// Research basis: PEASS “security software” noise + red-team OPSEC product discovery.
/// Safety and behavior: fires only with supporting path-to-impact (remote/weak prot/inject/high-value);
/// honest that path heuristics miss many agents; not a claim of “undetectable.”
public struct SecurityProductGapVector: Check {
    public static let id = "rootstock.vector.edr.security_product_gap"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard Self.hasCoverageGap(state), Self.hasSupportingSurface(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }


    private static func hasCoverageGap(_ state: CollectedState) -> Bool {
        state.securityProducts.filter(\.present).isEmpty || state.securityProducts.isEmpty
    }

    private static func hasSupportingSurface(_ state: CollectedState) -> Bool {
        remoteAccess(state) || weakProtections(state) || state.injectabilityHits.contains { !$0.riskFlags.isEmpty } || highValueSurface(state)
    }

    private static func remoteAccess(_ state: CollectedState) -> Bool {
        state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true || state.network?.fileSharingSMB == true
    }

    private static func weakProtections(_ state: CollectedState) -> Bool {
        state.protections?.sipEnabled == false || state.protections?.gatekeeperEnabled == false || state.protections?.fileVaultOn == false
    }

    private static func highValueSurface(_ state: CollectedState) -> Bool {
        state.credPaths.contains(where: \.exists) || state.browserMeta.contains(where: \.exists) || state.identity?.adBound == true || state.identity?.platformSSO == true
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let present = state.securityProducts.filter(\.present), absent = state.securityProducts.filter { !$0.present }
        let remote = Self.remoteAccess(state), weak = Self.weakProtections(state), inject = state.injectabilityHits.contains { !$0.riskFlags.isEmpty }, high = Self.highValueSurface(state)
        var evidence: [Evidence] = [Evidence(type: "edr_summary", detail: "securityProductsPresent=\(present.count) catalogEntries=\(state.securityProducts.count) " + "absentNamed=\(absent.count) (path heuristic only)")]
        for p in state.securityProducts.prefix(20) { evidence.append(Evidence(type: "product_probe", path: p.path, detail: "name=\(p.name) present=\(p.present)")) }
        if remote { evidence.append(Evidence(type: "supporting", detail: "remote/sharing posture elevated")) }
        if weak { evidence.append(Evidence(type: "supporting", detail: "protections weak/disabled")) }
        if inject { evidence.append(Evidence(type: "supporting", detail: "injectability risk flags present")) }
        if high { evidence.append(Evidence(type: "supporting", detail: "high-value identity/cred/browser surface")) }
        evidence.append(Evidence(type: "honesty", detail: "Missing path hits ≠ no EDR (system extensions, hidden agents, MDM-managed tools common)"))
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let noCoverage = state.securityProducts.filter(\.present).isEmpty, remote = remoteAccess(state), weak = weakProtections(state), inject = state.injectabilityHits.contains { !$0.riskFlags.isEmpty }
        let title = noCoverage && remote ? "EDR/security-product gap: no path hits with remote access surface" : (noCoverage && weak ? "EDR/security-product gap: no path hits with weak protections" : "EDR/security-product coverage thin or undetected with supporting attack surface")
        return Finding(id: Self.id, title: title, severity: (remote && weak) || (noCoverage && inject) ? .medium : .low, category: .securityProduct, resolution: .init(evidence: evidence, attackTechniques: ["T1518.001", "T1562.001", "T1082"], remediation: ["Confirm endpoint security via MDM inventory and System Extension lists - not only path probes", "Deploy managed EDR/XDR on high-value and remotely accessible hosts", "Treat assess OPSEC carefully when coverage is unknown (assume ESF consumers exist)", "OPSEC: this finding is a coverage gap signal for operators, not a stealth claim"], falsePositiveNotes: "Many commercial agents use non-catalog paths or pure system extensions. " + "False negatives expected; verify with enterprise inventory before remediating."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 12, esfExpected: ["OPEN"]))
    }
}
