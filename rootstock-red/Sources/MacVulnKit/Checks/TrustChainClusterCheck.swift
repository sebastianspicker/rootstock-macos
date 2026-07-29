import Foundation
import RootstockCore

/// Trust-chain vuln cluster: Gatekeeper × codesign × notarization-ish signals × inject.
///
/// Research basis: PEASS Gatekeeper + InjectCheck trust themes.
/// Safety and behavior: multi-rule ranked Findings over CollectedState; no bypass pack.
public struct TrustChainClusterCheck: Check {
    public static let id = "rootstock.check.vuln.trust_chain_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var findings: [Finding] = []
        if let f = Self.gatekeeperOff(state: state) { findings.append(f) }
        if let f = Self.unsignedWithInject(state: state) { findings.append(f) }
        if let f = Self.getTaskAllowCluster(state: state) { findings.append(f) }
        return findings
    }

    private static func gatekeeperOff(state: CollectedState) -> Finding? {
        guard state.protections?.gatekeeperEnabled == false else { return nil }
        return Finding(id: "\(id).gatekeeper_off", title: "Trust-chain cluster: Gatekeeper disabled", severity: .medium, category: .codesign, resolution: .init(evidence: [
                Evidence(type: "gatekeeper", detail: "gatekeeperEnabled=false"),
            ], attackTechniques: ["T1553.001", "T1204.002"], remediation: [
                "Re-enable Gatekeeper via MDM",
                "Block untrusted software installation paths on managed fleets",
            ], falsePositiveNotes: "Some labs intentionally disable GK - document in ROE"), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 12, esfExpected: ["OPEN"]))
    }

    private static func unsignedWithInject(state: CollectedState) -> Finding? {
        let unsigned = state.codesignSamples.filter { $0.signed == false }
        let inject = state.injectabilityHits.filter { !$0.riskFlags.isEmpty }
        guard !unsigned.isEmpty, !inject.isEmpty else { return nil }
        return Finding(id: "\(id).unsigned_with_inject", title: "Trust-chain cluster: unsigned samples with injectability flags", severity: .high, category: .codesign, resolution: .init(evidence: [
                Evidence(
                    type: "summary",
                    detail: "unsigned=\(unsigned.count) injectHits=\(inject.count)"
                ),
            ]
                + unsigned.prefix(10).map {
                    Evidence(type: "unsigned", path: $0.path, detail: "signed=false")
                }
                + inject.prefix(10).map {
                    Evidence(
                        type: "inject",
                        path: $0.path,
                        detail: "flags=\($0.riskFlags.joined(separator: ","))"
                    )
                }, attackTechniques: ["T1553", "T1055", "T1574"], remediation: [
                "Remove get-task-allow from release builds; enable Hardened Runtime",
                "Prefer signed, notarized tooling on engagement hosts",
            ], falsePositiveNotes: "Debug builds on engineering Macs commonly look like this"), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 22, esfExpected: ["OPEN"]))
    }

    private static func getTaskAllowCluster(state: CollectedState) -> Finding? {
        let gta = state.codesignSamples.filter { $0.getTaskAllow == true }
            + state.injectabilityHits.filter { $0.getTaskAllow == true }.map {
                CodesignSample(path: $0.path, signature: .init(getTaskAllow: true))
            }
        // Dedup paths
        var seen = Set<String>()
        let paths = gta.map(\.path).filter { seen.insert($0).inserted }
        guard !paths.isEmpty else { return nil }
        return Finding(id: "\(id).get_task_allow", title: "Trust-chain cluster: get-task-allow present (\(paths.count) paths)", severity: .medium, category: .codesign, resolution: .init(evidence: paths.prefix(20).map {
                Evidence(type: "get_task_allow", path: $0, detail: "get-task-allow=true")
            }, attackTechniques: ["T1055", "T1620"], remediation: [
                "Strip get-task-allow from App Store / production profiles",
                "Use development provisioning only on isolated build agents",
            ], falsePositiveNotes: "Expected on local Xcode debug builds"), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 18, esfExpected: ["OPEN", "GET_TASK"]))
    }
}
