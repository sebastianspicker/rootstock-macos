import Foundation
import RootstockCore

/// Path-to-impact: high-utility security/trust CLI dual-use surface (security, codesign, spctl, xattr).
///
/// Research basis: LOOBins security(1) / codesign recon; public macOS trust-chain tooling themes.
/// Safety and behavior: requires ≥2 high-utility CLIs or security+codesign pair; ranks quieter planner alts.
public struct SecurityCLIDualUseVector: Check {
    public static let id = "rootstock.vector.lool.security_cli_dual_use"
    public static let cost: CollectorCost = .low

    /// High-utility security/trust CLIs for dual-use ranking.
    private static let securityCLINames: Set<String> = [
        "security", "codesign", "spctl", "xattr",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let present = state.loobins.filter { $0.present && Self.securityCLINames.contains($0.name.lowercased()) }
        let names = Set(present.map { $0.name.lowercased() })
        let pair = names.contains("security") && names.contains("codesign")
        guard pair || present.count >= 2 else { return [] }
        return [Self.finding(state: state, present: present, names: names, pair: pair)]
    }

    private static func finding(state: CollectedState, present: [LOOBinHit], names: Set<String>, pair: Bool) -> Finding {
        let title = Self.title(present: present, names: names, pair: pair)
        return Finding(id: Self.id, title: title, severity: pair && present.count >= 3 ? .medium : .low, category: .lool, resolution: .init(evidence: evidence(state: state, present: present, pair: pair), attackTechniques: ["T1518", "T1082", "T1553"], remediation: ["For authorized recon prefer quieter planner discovery bins over security dump-* patterns", "Monitor anomalous security(1)/codesign/spctl process trees and Gatekeeper policy changes", "Alert on mass xattr quarantine clears and unexpected spctl --master-disable class activity", "OPSEC: dual-use CLI presence is expected on macOS; rank quieter alternatives first"], falsePositiveNotes: "security, codesign, spctl, and xattr ship with macOS. Finding is dual-use chain ranking, not malware or misconfiguration by itself."), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: pair ? 28 : 22, esfExpected: ["OPEN", "EXEC"]))
    }

    private static func evidence(state: CollectedState, present: [LOOBinHit], pair: Bool) -> [Evidence] {
        let names = present.map(\.name).sorted().joined(separator: ",")
        var evidence = [Evidence(type: "summary", detail: "securityCLIs=\(names) count=\(present.count) security+codesign=\(pair)")]
        if pair { evidence.append(Evidence(type: "chain", detail: "security + codesign both present - classic trust/keychain recon dual-use pair")) }
        evidence += present.sorted { $0.name < $1.name }.prefix(10).map { Evidence(type: "security_cli", path: $0.path, detail: "\($0.name) tactics=\($0.tactics.joined(separator: ","))") }
        evidence += plannerEvidence(state.lolPlans)
        evidence.append(Evidence(type: "opsec_honesty", detail: "security/codesign/spctl/xattr are stock dual-use tools - assess inventories only; does not dump keychains, strip quarantine, or disable Gatekeeper"))
        return evidence
    }

    private static func plannerEvidence(_ plans: [LOLPlanEntry]) -> [Evidence] {
        let quieter = plans.filter { ["discovery", "execute"].contains($0.goal) || securityCLINames.contains($0.name.lowercased()) }.sorted { $0.noiseScore < $1.noiseScore }
        guard !quieter.isEmpty else { return [Evidence(type: "planner", detail: "lolPlans empty - rank stock CLI presence only; prefer low-noise discovery later")] }
        let summary = quieter.prefix(8).map { "\($0.name)@\($0.noiseScore)/\($0.goal)" }.joined(separator: ", ")
        let entries = quieter.prefix(10).map { Evidence(type: "plan_entry", path: $0.path, detail: "goal=\($0.goal) noise=\($0.noiseScore) · \($0.rankReason)") }
        return [Evidence(type: "quieter_alternatives", detail: "planner quieter-first: \(summary)")] + entries
    }

    private static func title(present: [LOOBinHit], names: Set<String>, pair: Bool) -> String {
        if pair && names.contains("spctl") { return "Security CLI dual-use: security + codesign + spctl trust-chain toolkit" }
        if pair { return "Security CLI dual-use: security + codesign pair present" }
        return "Security CLI dual-use surface (\(present.count): \(present.map(\.name).sorted().joined(separator: ", ")))"
    }
}
