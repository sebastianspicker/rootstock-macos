import Foundation
import RootstockCore

/// Wave-12 compound: Mail rules automation × remote/FDA path-to-impact.
public struct MailRulesScriptCompoundVector: Check {
    public static let id = "rootstock.vector.persist.mail_rules_script_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.mailRulesAutomation
        let a = s?.mailAppPaths.count ?? 0
        let b = s?.rulesPlistPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin =
            state.esf?.clientPaths.isEmpty == true
            || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "mail_rules_compound",
                detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"
            ),
        ]
        if let s {
            for path in (s.mailAppPaths + s.rulesPlistPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Mail rules automation compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never reads Mail contents or modifies user Mail rules."))

        let severity: Severity
        if remote && fda {
            severity = .high
        } else if remote || fda || sensorThin {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(id: Self.id, title: remote
                    ? "Mail rules automation × remote compound"
                    : "Mail rules automation × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1114", "T1059", "T1546"], remediation: [
                    "Prioritize hosts co-locating Mail rules automation with remote/FDA amplifiers",
                    "Use Wave-12 lab plans under ROE for purple validation",
                    "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
                ], falsePositiveNotes: "Developer hosts may co-locate many dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"])),
        ]
    }
}
