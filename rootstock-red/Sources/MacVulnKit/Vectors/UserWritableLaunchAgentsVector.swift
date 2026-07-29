import Foundation
import RootstockCore

/// Persistence opportunity: user LaunchAgents directory is writable and agents already exist.
///
/// Honest about modern BTM user notification - not a silent implant claim.
public struct UserWritableLaunchAgentsVector: Check {
    public static let id = "rootstock.vector.persist.user_writable_launchagents"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let agents = state.launchAgents
        guard !agents.isEmpty else { return [] }

        let directory = Self.userLaunchAgentsDirectory(from: agents)
        let writable = FileManager.default.isWritableFile(atPath: directory.path)
        let likelyWritable = writable
            || directory.path.contains("/Users/")
            || directory.path.hasPrefix(FileManager.default.homeDirectoryForCurrentUser.path)
        guard likelyWritable else { return [] }

        return [Self.finding(agents: agents, directory: directory, writable: writable, state: state)]
    }

    private static func finding(
        agents: [LaunchAgentEntry],
        directory: URL,
        writable: Bool,
        state: CollectedState
    ) -> Finding {
        Finding(
            id: Self.id,
            title: "Persistence vector: user LaunchAgents writable (\(agents.count) agents)",
            severity: .medium,
            category: .persist,
            resolution: .init(
                evidence: evidence(agents: agents, directory: directory, writable: writable, state: state),
                attackTechniques: ["T1543.001", "T1547.015"],
                remediation: [
                    "Review unexpected LaunchAgents under ~/Library/LaunchAgents",
                    "Monitor LaunchAgents writes via ESF (OPEN/WRITE/CREATE) and BTM registration",
                    "OPSEC: claiming silent LaunchAgent install is false on modern macOS - BTM/user prompts raise detection risk (high OPSEC cost)",
                    "Prefer signed, user-visible apps over ad-hoc agent drops in authorized labs only",
                ],
                falsePositiveNotes: "User-writable LaunchAgents is normal; vector requires malicious or unexpected agent content"
            ),
            runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 72, tccDomains: [], esfExpected: ["OPEN", "WRITE", "CREATE", "USER_PROMPT"])
        )
    }

    private static func evidence(
        agents: [LaunchAgentEntry],
        directory: URL,
        writable: Bool,
        state: CollectedState
    ) -> [Evidence] {
        var result = [Evidence(
            type: "launchagents_dir",
            path: directory.path,
            detail: "writable=\(writable) likelyWritable=true agents=\(agents.count)"
        )]
        result += agents.prefix(20).map {
            Evidence(type: "launchagent", path: $0.path, detail: $0.label ?? "unlabeled")
        }
        result.append(btmEvidence(for: state))
        return result
    }

    private static func btmEvidence(for state: CollectedState) -> Evidence {
        if let btm = state.loginItems {
            return Evidence(
                type: "btm",
                path: btm.btmDirectoryPath,
                detail: "btmStorePresent=\(btm.btmStorePresent) - modern macOS may notify user of new background items"
            )
        }
        if let btmStorePresent = state.btmStorePresent {
            return Evidence(
                type: "btm",
                detail: "btmStorePresent=\(btmStorePresent) - BTM may surface new agents to the user"
            )
        }
        return Evidence(
            type: "btm_honesty",
            detail: "On modern macOS (Ventura+), Background Task Management may notify the user when new LaunchAgents/login items register - silent persistence is not guaranteed"
        )
    }

    private static func userLaunchAgentsDirectory(from agents: [LaunchAgentEntry]) -> URL {
        if let first = agents.first {
            return URL(fileURLWithPath: first.path).deletingLastPathComponent()
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents", isDirectory: true)
    }
}
