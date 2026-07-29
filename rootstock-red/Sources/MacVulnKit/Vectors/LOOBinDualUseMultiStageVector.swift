import Foundation
import RootstockCore

/// Path-to-impact: multi-stage dual-use LOOBin chains (discover → execute → persist).
///
/// Research basis: LOOBins catalog; Atomic multi-step techniques.
/// Safety and behavior: stage-aware chain with planner noise ranking; quieter alternatives;
/// distinct from single osascript+launchctl pair vector.
public struct LOOBinDualUseMultiStageVector: Check {
    public static let id = "rootstock.vector.lool.dual_use_multistage"
    public static let cost: CollectorCost = .low

    private static let discover: Set<String> = [
        "mdfind", "system_profiler", "codesign", "spctl", "ls", "find", "defaults",
    ]
    private static let execute: Set<String> = [
        "osascript", "bash", "zsh", "python3", "curl", "ditto", "installer",
    ]
    private static let persist: Set<String> = [
        "launchctl", "crontab", "sfltool", "bglist",
    ]
    private static let credentialish: Set<String> = [
        "security", "sqlite3", "dscl",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let names = Set(state.loobins.filter(\.present).map { $0.name.lowercased() })
        guard !names.isEmpty else { return [] }
        let disc = names.intersection(Self.discover)
        let exec = names.intersection(Self.execute)
        let pers = names.intersection(Self.persist)
        let cred = names.intersection(Self.credentialish)
        let stages = Self.stageCount(disc: disc, exec: exec, pers: pers, cred: cred)
        guard !disc.isEmpty && !exec.isEmpty && !pers.isEmpty || stages >= 3 else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }


    private static func stageCount(
        disc: Set<String>,
        exec: Set<String>,
        pers: Set<String>,
        cred: Set<String>
    ) -> Int {
        (disc.isEmpty ? 0 : 1)
            + (exec.isEmpty ? 0 : 1)
            + (pers.isEmpty ? 0 : 1)
            + (cred.isEmpty ? 0 : 1)
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let present = state.loobins.filter(\.present)
        let names = Set(present.map { $0.name.lowercased() })
        let disc = names.intersection(Self.discover)
        let exec = names.intersection(Self.execute)
        let pers = names.intersection(Self.persist)
        let cred = names.intersection(Self.credentialish)
        let stages = Self.stageCount(disc: disc, exec: exec, pers: pers, cred: cred)
        var evidence: [Evidence] = [
            Evidence(
                type: "stages",
                detail:
                    "discover=\(disc.sorted().joined(separator: ",")) "
                    + "execute=\(exec.sorted().joined(separator: ",")) "
                    + "persist=\(pers.sorted().joined(separator: ",")) "
                    + "credish=\(cred.sorted().joined(separator: ",")) "
                    + "stageCount=\(stages)"
            ),
        ]
        appendPlannerEvidence(from: state.lolPlans, to: &evidence)
        appendChainEvidence(for: state, to: &evidence)
        if exec.contains("osascript") {
            evidence.append(Evidence(type: "tcc_cost", detail: "osascript in execute stage - Automation TCC + high ESF EXEC noise"))
        }
        return evidence
    }

    private func appendPlannerEvidence(from plans: [LOLPlanEntry], to evidence: inout [Evidence]) {
        for goal in ["discovery", "execute", "persist"] {
            let ranked = plans.filter { $0.goal == goal }.sorted { $0.noiseScore < $1.noiseScore }
            if let best = ranked.first {
                evidence.append(
                    Evidence(
                        type: "planner_\(goal)",
                        path: best.path,
                        detail: "quieter \(goal): \(best.name) noise=\(best.noiseScore) · \(best.rankReason)"
                    )
                )
            }
        }
    }

    private func appendChainEvidence(for state: CollectedState, to evidence: inout [Evidence]) {
        let present = state.loobins.filter(\.present)
        let names = Set(present.map { $0.name.lowercased() })
        let disc = names.intersection(Self.discover)
        let exec = names.intersection(Self.execute)
        let pers = names.intersection(Self.persist)
        let cred = names.intersection(Self.credentialish)
        for bin in present where disc.contains(bin.name.lowercased())
            || exec.contains(bin.name.lowercased())
            || pers.contains(bin.name.lowercased())
            || cred.contains(bin.name.lowercased())
        {
            evidence.append(
                Evidence(
                    type: "chain_member",
                    path: bin.path,
                    detail: "\(bin.name) tactics=\(bin.tactics.joined(separator: ","))"
                )
            )
        }
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let names = Set(state.loobins.filter(\.present).map { $0.name.lowercased() })
        let disc = names.intersection(Self.discover)
        let exec = names.intersection(Self.execute)
        let pers = names.intersection(Self.persist)
        let cred = names.intersection(Self.credentialish)
        let stages = stageCount(disc: disc, exec: exec, pers: pers, cred: cred)
        let classic = !disc.isEmpty && !exec.isEmpty && !pers.isEmpty
        let title = classic
            ? "LOOBin multi-stage chain: discover→execute→persist" + (cred.isEmpty ? "" : " (+credential dual-use)")
            : "LOOBin dual-use multi-stage surface (\(stages) stages)"
        return Finding(id: Self.id, title: title, severity: classic && stages >= 3 ? .medium : .low, category: .lool, resolution: .init(evidence: evidence, attackTechniques: ["T1059", "T1059.002", "T1543.001", "T1218", "T1552"], remediation: [
                    "Prefer quieter planner discovery bins before osascript/curl in authorized tests",
                    "Monitor multi-stage process trees: mdfind/system_profiler → osascript → launchctl",
                    "Do not treat stock Apple dual-use bins as malware; focus on chain context",
                    "OPSEC: multi-stage chains accumulate ESF EXEC noise - stage deliberately",
                ], falsePositiveNotes: "All listed binaries are expected on stock macOS. Finding is chain utility, not IOC."), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: classic ? 58 : 42, tccDomains: exec.contains("osascript") ? ["Automation"] : [], esfExpected: ["OPEN", "EXEC"]))
    }
}
