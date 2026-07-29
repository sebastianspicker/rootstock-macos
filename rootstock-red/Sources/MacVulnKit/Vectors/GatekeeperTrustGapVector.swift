import Foundation
import RootstockCore

/// Path-to-impact: Gatekeeper disabled and/or unsigned/ad-hoc codesign samples.
///
/// Research basis: InjectCheck / PEASS Gatekeeper checks; red-team trust-chain assessment.
/// Safety and behavior: compounds GK posture with real codesign samples; not a notarization bypass pack.
public struct GatekeeperTrustGapVector: Check {
    public static let id = "rootstock.vector.codesign.gatekeeper_trust_gap"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard Self.hasWeakTrustSurface(state), Self.hasPathToImpact(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }


    private static func hasWeakTrustSurface(_ state: CollectedState) -> Bool {
        state.protections?.gatekeeperEnabled == false
            || state.codesignSamples.contains { $0.signed == false }
            || state.codesignSamples.contains {
                $0.getTaskAllow == true
                    || $0.disableLibraryValidation == true
                    || $0.allowDyldEnvironmentVariables == true
                    || $0.hardenedRuntime == false
            }
    }

    private static func hasPathToImpact(_ state: CollectedState) -> Bool {
        let unsigned = state.codesignSamples.filter { $0.signed == false }
        let dangerousEnt = state.codesignSamples.filter(Self.hasDangerousEntitlement)
        return state.protections?.gatekeeperEnabled == false
            || hasInjectSurface(state)
            || unsigned.count + dangerousEnt.count >= 2
            || (!unsigned.isEmpty && state.protections?.gatekeeperEnabled != true)
            || !dangerousEnt.isEmpty
    }

    private static func hasInjectSurface(_ state: CollectedState) -> Bool {
        !state.injectabilityHits.filter { !$0.riskFlags.isEmpty }.isEmpty
    }

    private static func hasDangerousEntitlement(_ sample: CodesignSample) -> Bool {
        sample.getTaskAllow == true
            || sample.disableLibraryValidation == true
            || sample.allowDyldEnvironmentVariables == true
            || sample.hardenedRuntime == false
    }


    private func evidence(for state: CollectedState) -> [Evidence] {
        let gk = state.protections?.gatekeeperEnabled
        let unsigned = state.codesignSamples.filter { $0.signed == false }
        let dangerousEnt = state.codesignSamples.filter {
            $0.getTaskAllow == true
                || $0.disableLibraryValidation == true
                || $0.allowDyldEnvironmentVariables == true
                || $0.hardenedRuntime == false
        }
        let inject = Self.hasInjectSurface(state)
        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "gatekeeperEnabled=\(gk.rootstockDescribe) unsigned=\(unsigned.count) "
                    + "dangerousEntSamples=\(dangerousEnt.count) injectCompound=\(inject)"
            ),
        ]
        if let notes = state.protections?.notes {
            evidence.append(contentsOf: notes.prefix(8).map { Evidence(type: "prot_note", detail: $0) })
        }
        for s in (unsigned + dangerousEnt).prefix(25) {
            evidence.append(
                Evidence(
                    type: "codesign_sample",
                    path: s.path,
                    detail:
                        "signed=\(s.signed.rootstockDescribe) HR=\(s.hardenedRuntime.rootstockDescribe) "
                        + "get-task-allow=\(s.getTaskAllow.rootstockDescribe) team=\(s.teamIdentifier ?? "none")"
                )
            )
        }
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let gkOff = state.protections?.gatekeeperEnabled == false
        let unsigned = state.codesignSamples.filter { $0.signed == false }
        let dangerousEnt = state.codesignSamples.filter {
            $0.getTaskAllow == true
                || $0.disableLibraryValidation == true
                || $0.allowDyldEnvironmentVariables == true
                || $0.hardenedRuntime == false
        }
        let inject = hasInjectSurface(state)
        let severity: Severity
        let title: String
        if gkOff && (!unsigned.isEmpty || inject) {
            severity = .high
            title = "Trust-chain gap: Gatekeeper off with weak codesign/inject surface"
        } else if gkOff {
            severity = .medium
            title = "Trust-chain gap: Gatekeeper disabled"
        } else if !unsigned.isEmpty && inject {
            severity = .medium
            title = "Trust-chain gap: unsigned/ad-hoc samples with inject surface (\(unsigned.count))"
        } else {
            severity = .low
            title = "Trust-chain surface: weak codesign samples (\(unsigned.count + dangerousEnt.count))"
        }
        return Finding(id: Self.id, title: title, severity: severity, category: .codesign, resolution: .init(evidence: evidence, attackTechniques: ["T1553.001", "T1204.002", "T1036", "T1553"], remediation: [
                    "Re-enable Gatekeeper (`spctl`) via MDM compliance baselines",
                    "Ship production builds with Developer ID + notarization; strip get-task-allow",
                    "Block ad-hoc unsigned tools on managed fleets where policy requires it",
                    "OPSEC: this is assess trust ranking - not a Gatekeeper bypass toolkit",
                ], falsePositiveNotes: "Engineering workstations often run unsigned debug builds. GK status may be unknown "
                    + "without privileged probes; corroborate with MDM inventory."), runtime: .init(confidence: gkOff ? .medium : .low, dryRunSafe: true, opsecScore: 16, esfExpected: ["OPEN"]))
    }

}
