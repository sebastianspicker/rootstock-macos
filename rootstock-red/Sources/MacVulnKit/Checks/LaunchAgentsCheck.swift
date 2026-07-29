/// Cluster/check: LaunchAgentsCheck - multi-signal posture ranking for assess pipeline.
import Foundation
import RootstockCore

public struct LaunchAgentsPresentCheck: Check {
    public static let id = "rootstock.check.persist.user_launchagents_present"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard !state.launchAgents.isEmpty else { return [] }
        return [
            Finding(id: Self.id, title: "User LaunchAgents present (\(state.launchAgents.count))", severity: .info, category: .persist, resolution: .init(evidence: state.launchAgents.prefix(20).map {
                    Evidence(type: "launchagent", path: $0.path, detail: $0.label ?? "unlabeled")
                }, attackTechniques: ["T1543.001"], remediation: [
                    "Review unexpected LaunchAgents",
                    "BTM may notify users of new background items on modern macOS",
                ], falsePositiveNotes: "Presence alone is not malicious; many legit apps install agents"), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 10, esfExpected: ["OPEN"])),
        ]
    }
}

/// System-scope LaunchAgents/Daemons under /Library (when present).
public struct SystemLaunchdInventoryCheck: Check {
    public static let id = "rootstock.check.persist.system_launchd_inventory"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let agents = state.systemLaunchAgents
        let daemons = state.launchDaemons
        let combined = agents + daemons
        guard !combined.isEmpty else { return [] }

        var evidence: [Evidence] = []
        evidence.append(
            Evidence(
                type: "summary",
                detail: "systemLaunchAgents=\(agents.count) launchDaemons=\(daemons.count)"
            )
        )
        for entry in agents.prefix(15) {
            evidence.append(
                Evidence(type: "system_launchagent", path: entry.path, detail: entry.label ?? "unlabeled")
            )
        }
        for entry in daemons.prefix(15) {
            evidence.append(
                Evidence(type: "launchdaemon", path: entry.path, detail: entry.label ?? "unlabeled")
            )
        }

        return [
            Finding(id: Self.id, title: "System launchd inventory (\(combined.count) plists under /Library)", severity: .info, category: .persist, resolution: .init(evidence: evidence, attackTechniques: ["T1543.001", "T1543.004"], remediation: [
                    "Review unexpected /Library LaunchAgents and LaunchDaemons",
                    "Prefer signed vendor packages; watch for unlabeled or writable plists",
                ], falsePositiveNotes: "Vendor agents/daemons under /Library are common on managed Macs"), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 10, esfExpected: ["OPEN"])),
        ]
    }
}
