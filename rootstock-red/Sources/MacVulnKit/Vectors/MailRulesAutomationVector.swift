import Foundation
import RootstockCore

/// Path-to-impact: Mail rules / Apple Mail automation persistence.
///
/// Research basis: Mail rules automation 2025–26 themes.
/// Safety and behavior: path compounds with remote/FDA amplifiers; never reads Mail contents or modifies user Mail rules.
public struct MailRulesAutomationVector: Check {
    public static let id = "rootstock.vector.persist.mail_rules_automation"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.mailRulesAutomation
        let a = s?.mailAppPaths.count ?? 0
        let b = s?.rulesPlistPaths.count ?? 0
        let c = s?.scriptingAdjacentPaths.count ?? 0
        let surface = s?.rulesSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.mail_rules_automation"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true

        var evidence: [Evidence] = [
            Evidence(
                type: "mail_rules_summary",
                detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"
            ),
        ]
        if let s {
            for path in (s.mailAppPaths + s.rulesPlistPaths + s.scriptingAdjacentPaths).prefix(12) {
                evidence.append(Evidence(type: "mail_rules_path", path: path, detail: "Mail rules automation path"))
            }
            for n in s.notes.prefix(6) {
                evidence.append(Evidence(type: "mail_rules_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail: "Assess never reads Mail contents or modifies user Mail rules."
            )
        )

        let severity: Severity
        if remote && fda && a + b >= 3 {
            severity = .high
        } else if remote || fda || a + b >= 2 {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(id: Self.id, title: remote
                    ? "Mail rules automation with remote access amplifier"
                    : "Mail rules / Apple Mail automation persistence", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1114", "T1059", "T1546"], remediation: [
                    "Inventory and baseline Mail rules automation paths via MDM/EDR",
                    "Correlate unexpected path co-presence with delivery timelines",
                    "Prioritize hosts with remote/FDA amplifiers",
                    "OPSEC: Rootstock Red never reads Mail contents or modifies user Mail rules",
                ], falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA amplifiers."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"])),
        ]
    }
}
