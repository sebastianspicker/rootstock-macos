import Foundation
import RootstockCore

/// Path-to-impact: Screen Recording / Accessibility TCC dual-use surface (non-prompting).
///
/// Research basis: LOOBins screencapture; public TCC screen/accessibility abuse themes.
/// Safety and behavior: notes + planner tccImpact + loobin presence only; never prompts TCC dialogs.
public struct ScreenAccessibilitySurfaceVector: Check {
    public static let id = "rootstock.vector.tcc.screen_accessibility_surface"
    public static let cost: CollectorCost = .low

    private static let screenKeywords = [
        "screen recording", "screen_recording", "screencapture", "screen capture",
        "capture screen", "display capture",
    ]
    private static let accessibilityKeywords = [
        "accessibility", "ax_", "trusted accessibility", "assistive",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let forcedSignals = collectorForcedSignals(in: state)
        let matchedNotes = matchingTCCNotes(in: state)
        let impactPlans = impactedPlans(in: state)
        let screencapture = screenCaptureLOOBin(in: state)
        var evidence = forcedSignals.evidence
        var signals = forcedSignals.isPresent ? ["collector_force"] : []

        if !matchedNotes.isEmpty {
            signals.append("tcc_notes")
            for note in matchedNotes.prefix(12) {
                evidence.append(Evidence(type: "tcc_note", detail: note))
            }
        }
        if !impactPlans.isEmpty {
            signals.append("lol_plans_tcc")
            evidence.append(contentsOf: impactPlanEvidence(from: impactPlans))
        }
        if let sc = screencapture {
            signals.append("screencapture_loobin")
            evidence.append(
                Evidence(
                    type: "loobin",
                    path: sc.path,
                    detail: "screencapture tactics=\(sc.tactics.joined(separator: ","))"
                )
            )
        }

        guard !signals.isEmpty else { return [] }

        evidence.append(contentsOf: quieterAlternativeEvidence(from: state))
        return [makeFinding(ScreenAccessibilityEvaluation(
            evidence: evidence,
            signals: signals,
            forcedNotes: forcedSignals.notes,
            matchedNotes: matchedNotes,
            impactPlans: impactPlans,
            screencapturePresent: screencapture != nil
        ))]
    }

    private struct ScreenAccessibilityForcedSignals {
        let isPresent: Bool
        let notes: [String]
        let evidence: [Evidence]
    }

    private struct ScreenAccessibilityEvaluation {
        let evidence: [Evidence]
        let signals: [String]
        let forcedNotes: [String]
        let matchedNotes: [String]
        let impactPlans: [LOLPlanEntry]
        let screencapturePresent: Bool
    }

    private func collectorForcedSignals(in state: CollectedState) -> ScreenAccessibilityForcedSignals {
        guard let note = state.collectorNotes["tcc.screen_accessibility"] else {
            return ScreenAccessibilityForcedSignals(isPresent: false, notes: [], evidence: [])
        }
        let notes = note.split(separator: "|").map {
            String($0).trimmingCharacters(in: .whitespaces)
        }.filter { !$0.isEmpty }
        let evidence = notes.prefix(12).map { Evidence(type: "collector_note", detail: $0) }
        return ScreenAccessibilityForcedSignals(isPresent: true, notes: notes, evidence: evidence)
    }

    private func matchingTCCNotes(in state: CollectedState) -> [String] {
        (state.tcc?.notes ?? []).filter { note in
            let lower = note.lowercased()
            let screenMatch = Self.screenKeywords.contains { lower.contains($0) }
            let accessibilityMatch = Self.accessibilityKeywords.contains { lower.contains($0) }
            return screenMatch || accessibilityMatch
        }
    }

    private func impactedPlans(in state: CollectedState) -> [LOLPlanEntry] {
        state.lolPlans.filter { plan in
            plan.tccImpact.contains { impact in
                let lower = impact.lowercased()
                return lower.contains("screen") || lower.contains("accessibility")
            }
        }
    }

    private func screenCaptureLOOBin(in state: CollectedState) -> LOOBinHit? {
        state.loobins.first { $0.present && $0.name.lowercased() == "screencapture" }
    }

    private func impactPlanEvidence(from plans: [LOLPlanEntry]) -> [Evidence] {
        plans.prefix(10).map { plan in
            Evidence(
                type: "planner_tcc",
                path: plan.path,
                detail: "\(plan.name) noise=\(plan.noiseScore) "
                    + "tcc=\(plan.tccImpact.joined(separator: ",")) · \(plan.rankReason)"
            )
        }
    }

    private func quieterAlternativeEvidence(from state: CollectedState) -> [Evidence] {
        state.lolPlans
            .filter { $0.goal == "discovery" || $0.goal == "execute" }
            .sorted { $0.noiseScore < $1.noiseScore }
            .prefix(6)
            .map { entry in
                Evidence(
                    type: "planner_alt",
                    path: entry.path,
                    detail: "\(entry.name) noise=\(entry.noiseScore) "
                        + "tcc=\(entry.tccImpact.joined(separator: ","))"
                )
            }
    }

    private func makeFinding(_ evaluation: ScreenAccessibilityEvaluation) -> Finding {
        let multi = evaluation.signals.count >= 2
            || (!evaluation.forcedNotes.isEmpty && evaluation.screencapturePresent)
        var findingsEvidence = evaluation.evidence
        findingsEvidence.insert(
            Evidence(
                type: "summary",
                detail: "signals=\(evaluation.signals.joined(separator: ",")) "
                    + "tccNoteHits=\(evaluation.matchedNotes.count) impactPlans=\(evaluation.impactPlans.count) "
                    + "screencapture=\(evaluation.screencapturePresent) forced=\(!evaluation.forcedNotes.isEmpty) "
                    + "(non-prompting - no TCC dialogs forced)"
            ),
            at: 0
        )
        findingsEvidence.append(tccHonestyEvidence())
        return Finding(
            id: Self.id,
            title: title(
                screencapturePresent: evaluation.screencapturePresent,
                forcedNotes: evaluation.forcedNotes,
                matchedNotes: evaluation.matchedNotes,
                impactPlans: evaluation.impactPlans
            ),
            severity: multi ? .medium : .low,
            category: .tcc,
            resolution: .init(
                evidence: findingsEvidence,
                attackTechniques: ["T1113", "T1056.002", "T1222"],
                remediation: [
                    "Review Screen Recording and Accessibility grants in System Settings → Privacy & Security",
                    "Prefer PPPC profiles for approved assistive / remote-support tools only",
                    "Monitor screencapture and Accessibility API abuse via EDR/ESF",
                    "OPSEC: assess is non-prompting - never force Screen Recording / Accessibility dialogs",
                ],
                falsePositiveNotes: "screencapture ships with macOS; presence alone is dual-use ranking, not malware. "
                    + "TCC grant state is not fully enumerable without privileged/TCC.db access."
            ),
            runtime: .init(
                confidence: multi ? .medium : .low,
                dryRunSafe: true,
                opsecScore: multi ? 45 : 30,
                tccDomains: tccDomains(
                    screencapturePresent: evaluation.screencapturePresent,
                    impactPlans: evaluation.impactPlans,
                    matchedNotes: evaluation.matchedNotes
                ),
                esfExpected: ["OPEN", "EXEC", "USER_PROMPT"]
            )
        )
    }

    private func title(
        screencapturePresent: Bool,
        forcedNotes: [String],
        matchedNotes: [String],
        impactPlans: [LOLPlanEntry]
    ) -> String {
        if screencapturePresent && (!impactPlans.isEmpty || !matchedNotes.isEmpty) {
            return "Screen/Accessibility TCC surface: screencapture + TCC impact signals"
        }
        if screencapturePresent {
            return "Screen capture dual-use surface: screencapture present (TCC-honest)"
        }
        if !forcedNotes.isEmpty {
            return "Screen/Accessibility surface: collector-forced TCC signals"
        }
        return "Screen Recording / Accessibility TCC surface signals present"
    }

    private func tccDomains(
        screencapturePresent: Bool,
        impactPlans: [LOLPlanEntry],
        matchedNotes: [String]
    ) -> [String] {
        var domains: [String] = []
        if screencapturePresent || hasScreenImpact(impactPlans, notes: matchedNotes) {
            domains.append("ScreenRecording")
        }
        if hasAccessibilityImpact(impactPlans, notes: matchedNotes) {
            domains.append("Accessibility")
        }
        return domains.isEmpty ? ["ScreenRecording", "Accessibility"] : domains
    }

    private func hasScreenImpact(_ plans: [LOLPlanEntry], notes: [String]) -> Bool {
        plans.contains { $0.tccImpact.contains { $0.localizedCaseInsensitiveContains("screen") } }
            || notes.contains { $0.localizedCaseInsensitiveContains("screen") }
    }

    private func hasAccessibilityImpact(_ plans: [LOLPlanEntry], notes: [String]) -> Bool {
        plans.contains { $0.tccImpact.contains { $0.localizedCaseInsensitiveContains("accessibility") } }
            || notes.contains { $0.localizedCaseInsensitiveContains("accessibility") }
    }

    private func tccHonestyEvidence() -> Evidence {
        Evidence(
            type: "tcc_honesty",
            detail: "Screen Recording and Accessibility often require user prompts or prior grants; "
                + "Rootstock Red assess uses non-prompting inventory only"
        )
    }
}
