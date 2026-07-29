import Foundation
import RootstockCore

/// PEASS-class privilege-escalation vector: user-writable privileged paths.
///
/// Research basis: MacPEAS writable-path breadth (LaunchDaemons, helpers, system agents).
/// Safety and behavior: pure evaluation over CollectedState + FileManager writability (no bash process
/// storms); typed Finding with ATT&CK, SIP honesty, remediation, and FP notes.
public struct WritablePrivilegedPathsVector: Check {
    public static let id = "rootstock.vector.privesc.writable_privileged_paths"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let candidates = Self.candidatePaths(from: state)
        let hits = Self.writableHits(from: candidates)
        guard !hits.isEmpty else { return [] }
        return [Self.finding(for: hits, candidateCount: candidates.count, state: state)]
    }


    private struct WritablePathHit {
        let path: String
        let kind: String
        let reason: String
    }

    private static func writableHits(from candidates: [Candidate]) -> [WritablePathHit] {
        candidates.compactMap { candidate in
            let pathWritable = FileManager.default.isWritableFile(atPath: candidate.path)
            let parent = URL(fileURLWithPath: candidate.path).deletingLastPathComponent().path
            let parentWritable = FileManager.default.isWritableFile(atPath: parent)
            guard candidate.forceWritable || pathWritable || parentWritable else { return nil }
            let reason = candidate.forceWritable
                ? "collector_flagged_writable"
                : pathWritable ? "path_writable" : "parent_writable"
            return WritablePathHit(path: candidate.path, kind: candidate.kind, reason: reason)
        }
    }

    private static func finding(
        for hits: [WritablePathHit],
        candidateCount: Int,
        state: CollectedState
    ) -> Finding {
        Finding(
            id: Self.id,
            title: "Privilege-escalation vector: user-writable privileged paths (\(hits.count))",
            severity: severity(for: hits, state: state),
            category: .misconfig,
            resolution: .init(
                evidence: evidence(for: hits, candidateCount: candidateCount, state: state),
                attackTechniques: ["T1068", "T1222", "T1543.001", "T1543.004", "T1574"],
                remediation: [
                    "Fix ownership/permissions on writable LaunchDaemons, helpers, and system agents",
                    "Ensure privileged paths are root:wheel and not group/world writable",
                    "Re-enable SIP if disabled; validate with csrutil status via MDM inventory",
                    "OPSEC: assess uses FileManager writability checks only - no PEASS shell recursion",
                ],
                falsePositiveNotes: "Lab temp trees may simulate privileged path names. On stock SIP-on hosts, true writable system LaunchDaemons are rare; verify before emergency change control."
            ),
            runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN"])
        )
    }

    private static func evidence(
        for hits: [WritablePathHit],
        candidateCount: Int,
        state: CollectedState
    ) -> [Evidence] {
        var result = [Evidence(
            type: "summary",
            detail: "privilegedCandidates=\(candidateCount) userWritableHits=\(hits.count) (PEASS-class rule, API-first - no shell storm)"
        )]
        result += hits.prefix(40).map {
            Evidence(type: "writable_privileged_path", path: $0.path, detail: "kind=\($0.kind) reason=\($0.reason)")
        }
        if state.protections?.sipEnabled == true {
            result.append(Evidence(type: "sip_honesty", detail: "SIP enabled - many /System paths remain immutable even if mis-reported; focus remediations on /Library user-writable locations"))
        } else if state.protections?.sipEnabled == false {
            result.append(Evidence(type: "sip_off", detail: "SIP disabled compounds writable privileged paths into higher impact"))
        }
        return result
    }

    private static func severity(for hits: [WritablePathHit], state: CollectedState) -> Severity {
        let highImpact = hits.contains { $0.kind.contains("daemon") || $0.kind.contains("helper") || $0.kind.contains("sygext") }
        if state.protections?.sipEnabled == false && highImpact { return .critical }
        return highImpact ? .high : .medium
    }

    // MARK: - Candidates

    struct Candidate {
        var path: String
        var kind: String
        /// When collector/synthetic state already asserts writability (tests + future collector).
        var forceWritable: Bool
    }

    static func candidatePaths(from state: CollectedState) -> [Candidate] {
        let candidates = launchCandidates(from: state) + collectorNoteCandidates(from: state.collectorNotes)
        var seen = Set<String>()
        return candidates.filter { seen.insert($0.path).inserted }
    }

    private static func launchCandidates(from state: CollectedState) -> [Candidate] {
        state.systemLaunchAgents.map { Candidate(path: $0.path, kind: "system_launch_agent", forceWritable: false) }
            + state.launchDaemons.map { Candidate(path: $0.path, kind: "launch_daemon", forceWritable: false) }
            + state.privilegedHelperTools.map { Candidate(path: $0, kind: "privileged_helper", forceWritable: false) }
            + state.systemExtensionPaths.map { Candidate(path: $0, kind: "system_extension", forceWritable: false) }
    }

    private static func collectorNoteCandidates(from notes: [String: String]) -> [Candidate] {
        notes.flatMap { (key, value) -> [Candidate] in
            let lowercasedKey = key.lowercased()
            guard lowercasedKey.contains("privesc"), lowercasedKey.contains("writable") else { return [] }
            return candidates(fromCollectorNoteValue: value)
        }
    }

    private static func candidates(fromCollectorNoteValue value: String) -> [Candidate] {
        if value.contains("|") {
            return value.split(separator: "|").compactMap { part in
                let path = String(part).trimmingCharacters(in: .whitespaces)
                return path.isEmpty ? nil : Candidate(path: path, kind: "collector_note_writable", forceWritable: true)
            }
        }
        return value.hasPrefix("/") ? [Candidate(path: value, kind: "collector_note_writable", forceWritable: true)] : []
    }
}
