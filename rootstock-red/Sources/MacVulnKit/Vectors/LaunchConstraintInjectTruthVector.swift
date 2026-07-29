import Foundation
import RootstockCore

/// Path-to-impact: launch-constraint honesty × injectability entitlement truth.
///
/// Research basis: InjectCheck HR/LV flags; Apple launch-constraint documentation.
/// Safety and behavior: constrained vs unconstrained-risk sets; never claims successful injection.
public struct LaunchConstraintInjectTruthVector: Check {
    public static let id = "rootstock.vector.inject.launch_constraint_truth"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws
        -> [Finding]
    {
        guard Self.hasRisk(state) else { return [] }
        return [Self.finding(for: state)]
    }

    private static func hasRisk(_ state: CollectedState) -> Bool {
        let lc = state.launchConstraints
        let unconstrained = lc?.unconstrainedRiskPaths ?? []
        let riskyInject = state.injectabilityHits.filter {
            !$0.riskFlags.isEmpty
                || $0.getTaskAllow == true
                || $0.disableLibraryValidation == true
                || $0.hardenedRuntime == false
        }
        return !unconstrained.isEmpty || !riskyInject.isEmpty || !state.dylibRiskHits.isEmpty
    }

    private static func finding(for state: CollectedState) -> Finding {
        let presentation = Self.presentation(for: state)
        return Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .codesign, resolution: .init(evidence: evidence(for: state), attackTechniques: ["T1574.006", "T1055", "T1548"], remediation: [
                "Enable Hardened Runtime; remove get-task-allow from production builds",
                "Avoid disable-library-validation except for narrowly justified plugins",
                "Prefer apps that ship launch constraints for privileged spawn relationships",
                "OPSEC: codesign probes are medium noise under ESF - sample, don't mass-scan",
            ], falsePositiveNotes: "Developer and Electron apps often ship with weaker entitlements by design. "
                + "Constraint artifacts may exist only inside signature blobs not listed as files."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 40, esfExpected: ["OPEN", "EXEC"]))
    }

    private static func evidence(for state: CollectedState) -> [Evidence] {
        let unconstrained = state.launchConstraints?.unconstrainedRiskPaths ?? []
        let constrained = state.launchConstraints?.constrainedPaths ?? []
        let riskyInject = riskyInjectabilityHits(state)
        return summaryEvidence(
            unconstrained: unconstrained, constrained: constrained, riskyInject: riskyInject,
            dylibs: state.dylibRiskHits)
            + pathEvidence(unconstrained: unconstrained, constrained: constrained)
            + injectEvidence(riskyInject)
            + dylibEvidence(state.dylibRiskHits)
            + launchConstraintNotes(state.launchConstraints?.notes ?? [])
    }

    private static func riskyInjectabilityHits(_ state: CollectedState) -> [InjectabilityHit] {
        state.injectabilityHits.filter {
            !$0.riskFlags.isEmpty || $0.getTaskAllow == true || $0.disableLibraryValidation == true
                || $0.hardenedRuntime == false
        }
    }

    private static func summaryEvidence(
        unconstrained: [String], constrained: [String], riskyInject: [InjectabilityHit],
        dylibs: [DylibRiskHit]
    ) -> [Evidence] {
        [
            Evidence(
                type: "summary",
                detail:
                    "unconstrainedRisk=\(unconstrained.count) constrainedArtifacts=\(constrained.count) "
                    + "injectHits=\(riskyInject.count) dylibRisk=\(dylibs.count)"),
            Evidence(
                type: "honesty",
                detail:
                    "Launch constraints and library validation reduce (not eliminate) load/inject "
                    + "classes. This finding is surface truth, not a working exploit."),
        ]
    }

    private static func pathEvidence(unconstrained: [String], constrained: [String]) -> [Evidence] {
        unconstrained.prefix(12).map {
            Evidence(
                type: "unconstrained_risk", path: $0,
                detail: "risk flags without observed constraint artifact")
        }
            + constrained.prefix(8).map {
                Evidence(
                    type: "constraint_artifact", path: $0, detail: "constraint-ish path present")
            }
    }

    private static func injectEvidence(_ hits: [InjectabilityHit]) -> [Evidence] {
        hits.prefix(12).map {
            Evidence(
                type: "inject_flags", path: $0.path,
                detail: "HR=\($0.hardenedRuntime.rootstockDescribe) "
                    + "get-task-allow=\($0.getTaskAllow.rootstockDescribe) disable-LV=\($0.disableLibraryValidation.rootstockDescribe) "
                    + "flags=\($0.riskFlags.joined(separator: ","))")
        }
    }

    private static func dylibEvidence(_ hits: [DylibRiskHit]) -> [Evidence] {
        hits.prefix(8).map {
            Evidence(
                type: "dylib_risk", path: $0.path,
                detail: "weakDylibs=\($0.weakDylibs.prefix(4).joined(separator: ","))")
        }
    }

    private static func launchConstraintNotes(_ notes: [String]) -> [Evidence] {
        notes.prefix(8).map { Evidence(type: "lc_note", detail: $0) }
    }

    private static func presentation(for state: CollectedState) -> (
        severity: Severity, title: String
    ) {
        let unconstrained = state.launchConstraints?.unconstrainedRiskPaths ?? []
        let riskyInject = riskyInjectabilityHits(state)
        if riskyInject.contains(where: { $0.getTaskAllow == true && $0.hardenedRuntime == false })
            || unconstrained.count >= 2
        {
            return (.high, "Inject truth: weak HR/get-task-allow without launch-constraint cover")
        }
        if !riskyInject.isEmpty || !unconstrained.isEmpty {
            return (.medium, "Inject truth: library-validation / constraint surface risk")
        }
        return (.low, "Inject truth: dylib load-command risk surface")
    }

}
