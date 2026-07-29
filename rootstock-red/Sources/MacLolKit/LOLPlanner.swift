import Foundation
import RootstockCore

/// Ranked LOOBin selection with noise and TCC-impact heuristics.
public struct RankedPlanEntry: Sendable, Equatable {
    public var loobin: LOOBin
    public var goal: LOLPlanner.Goal
    /// 0–100; higher = noisier / more OPSEC risk.
    public var noiseScore: Int
    public var tccImpact: [String]
    public var rankReason: String

    public init(
        loobin: LOOBin,
        goal: LOLPlanner.Goal,
        noiseScore: Int,
        tccImpact: [String] = [],
        rankReason: String = ""
    ) {
        self.loobin = loobin
        self.goal = goal
        self.noiseScore = noiseScore
        self.tccImpact = tccImpact
        self.rankReason = rankReason
    }

    /// Codable snapshot for CollectedState.
    public func asPlanEntry() -> LOLPlanEntry {
        LOLPlanEntry(
            name: loobin.name,
            path: loobin.path,
            goal: goal.rawValue,
            noiseScore: noiseScore,
            tccImpact: tccImpact,
            rankReason: rankReason
        )
    }
}

/// Goal-driven LOOBin planner: ranks present catalog entries by noise (quieter first).
public struct LOLPlanner: Sendable {
    public enum Goal: String, Sendable, CaseIterable {
        case download
        case execute
        case exfil
        case persist
        case discovery
    }

    public var catalog: LOOBinCatalog

    public init(catalog: LOOBinCatalog) {
        self.catalog = catalog
    }

    /// Rank present LOOBins suitable for `goal`, sorted by noise ascending (quieter first).
    public func plan(goal: Goal) -> [RankedPlanEntry] {
        let inventory = catalog.inventory().filter(\.present)
        let presentNames = Set(inventory.map(\.name))
        let candidates = catalog.entries.filter { presentNames.contains($0.name) }.filter {
            Self.matches(goal: goal, bin: $0)
        }

        return candidates.map { bin in
            let noise = Self.noiseScore(for: bin)
            let tcc = Self.tccImpact(for: bin)
            let reason = Self.rankReason(for: bin, goal: goal, noise: noise, tcc: tcc)
            return RankedPlanEntry(
                loobin: bin,
                goal: goal,
                noiseScore: noise,
                tccImpact: tcc,
                rankReason: reason
            )
        }
        .sorted { lhs, rhs in
            if lhs.noiseScore != rhs.noiseScore {
                return lhs.noiseScore < rhs.noiseScore
            }
            return lhs.loobin.name < rhs.loobin.name
        }
    }

    /// Plans for multiple goals, each capped at `topN` quietest entries.
    public func plan(goals: [Goal], topN: Int = 5) -> [RankedPlanEntry] {
        goals.flatMap { Array(plan(goal: $0).prefix(topN)) }
    }

    // MARK: - Heuristics

    private static func matches(goal: Goal, bin: LOOBin) -> Bool {
        let tactics = Set(bin.tactics.map { $0.lowercased() })
        return tactics.contains(where: { tacticMatches(goal: goal, tactic: $0) })
            || goalBins[goal, default: []].contains(bin.name)
    }

    private static let goalBins: [Goal: [String]] = [
        .discovery: ["system_profiler", "mdfind", "codesign", "profiles"],
        .persist: ["launchctl", "profiles"], .execute: ["osascript", "launchctl"],
        .exfil: ["screencapture", "sqlite3", "security", "mdfind"],
        .download: ["screencapture", "sqlite3", "security", "mdfind"],
    ]

    private static func tacticMatches(goal: Goal, tactic: String) -> Bool {
        switch goal {
        case .discovery: return tactic.contains("discovery")
        case .persist: return tactic.contains("persist")
        case .execute: return tactic.contains("execution")
        case .exfil, .download: return ["collection", "discovery", "credential"].contains { tactic.contains($0) }
        }
    }

    /// Noise score 0–100. Higher = more telemetry / human-visible risk.
    public static func noiseScore(for bin: LOOBin) -> Int {
        if let score = namedNoise[bin.name.lowercased()] { return score }
        return tacticNoise(for: bin.tactics.map { $0.lowercased() })
    }

    private static let namedNoise = ["system_profiler": 15, "mdfind": 40, "xattr": 30, "codesign": 35, "launchctl": 50, "profiles": 55, "sqlite3": 55, "security": 78, "osascript": 85, "screencapture": 90]
    private static func tacticNoise(for tactics: [String]) -> Int {
        let scores = [("credential", 70), ("execution", 65), ("persist", 55), ("collection", 60), ("discovery", 35)]
        return scores.first(where: { needle, _ in tactics.contains { $0.contains(needle) } })?.1 ?? 50
    }

    public static func tccImpact(for bin: LOOBin) -> [String] {
        ["screencapture": ["Screen Recording"], "osascript": ["Automation", "Accessibility"], "security": ["Keychain"], "sqlite3": ["Full Disk Access"]][bin.name.lowercased()] ?? []
    }

    private static func rankReason(
        for bin: LOOBin,
        goal: Goal,
        noise: Int,
        tcc: [String]
    ) -> String {
        let band: String
        switch noise {
        case 0..<30: band = "low noise"
        case 30..<60: band = "medium noise"
        case 60..<80: band = "high noise"
        default: band = "very high noise"
        }
        let tccPart = tcc.isEmpty ? "no TCC domain" : "TCC: \(tcc.joined(separator: ", "))"
        let tactics = bin.tactics.isEmpty ? "unspecified tactics" : bin.tactics.joined(separator: "/")
        return "\(goal.rawValue): \(bin.name) \(band) (\(noise)) · \(tccPart) · \(tactics)"
    }
}
