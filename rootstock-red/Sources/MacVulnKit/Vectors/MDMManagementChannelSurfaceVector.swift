import Foundation
import RootstockCore

/// Path-to-impact: active MDM / management channel (opposite of management_gap).
///
/// Fires when the host is enrolled or shows management signals (vendors, PPPC, managed prefs).
/// Narrative: high-value for authorized red-team / also attacker lateral if the channel is compromised.
///
/// Research basis: enterprise UEM recon themes; never Jamf script push.
/// Safety and behavior: typed Finding with ATT&CK + OPSEC; no management-action delivery.
public struct MDMManagementChannelSurfaceVector: Check {
    public static let id = "rootstock.vector.mdm.management_channel_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let mdm = state.mdm else { return [] }
        let enrolled = mdm.enrolled == true
        let vendors = !mdm.vendorHints.isEmpty
        let pppc = mdm.pppcPolicyPresent == true
        let managedPrefs = !mdm.managedPreferenceNames.isEmpty
        let profiles = (mdm.profileFileCount ?? 0) > 0 || mdm.profileStoreReadable == true
        guard enrolled || vendors || pppc || managedPrefs else { return [] }

        let signalCount = primarySignalCount(
            enrolled: enrolled, vendors: vendors, pppc: pppc, managedPrefs: managedPrefs
        )
        let evidence = evidence(for: state, profiles: profiles)
        return [Self.finding(for: state, signalCount: signalCount, evidence: evidence)]
    }


    private func primarySignalCount(
        enrolled: Bool,
        vendors: Bool,
        pppc: Bool,
        managedPrefs: Bool
    ) -> Int {
        (enrolled ? 1 : 0) + (vendors ? 1 : 0) + (pppc ? 1 : 0) + (managedPrefs ? 1 : 0)
    }

    private func evidence(for state: CollectedState, profiles: Bool) -> [Evidence] {
        guard let mdm = state.mdm else { return [] }
        var evidence: [Evidence] = [
            Evidence(
                type: "mdm_summary",
                detail:
                    "enrolled=\(mdm.enrolled.rootstockDescribe) vendors=\(mdm.vendorHints.count) "
                    + "managedPrefs=\(mdm.managedPreferenceNames.count) "
                    + "pppcPolicyPresent=\(mdm.pppcPolicyPresent.rootstockDescribe) "
                    + "profileFiles=\(Self.describeInt(mdm.profileFileCount)) "
                    + "profileStoreReadable=\(mdm.profileStoreReadable.rootstockDescribe)"
            ),
            Evidence(
                type: "path_to_impact",
                detail:
                    "Management channel is high-value for authorized RT (policy/PPPC/compliance pivot) "
                    + "and for attackers if the channel is compromised (T1072 software deployment / "
                    + "T1484 domain or tenant policy modification class)"
            ),
        ]
        for vendor in mdm.vendorHints.prefix(12) {
            evidence.append(Evidence(type: "vendor_hint", detail: vendor))
        }
        for name in mdm.managedPreferenceNames.prefix(15) {
            evidence.append(Evidence(type: "managed_pref", detail: name))
        }
        for note in mdm.notes.prefix(10) {
            evidence.append(Evidence(type: "note", detail: note))
        }
        if profiles {
            evidence.append(Evidence(type: "profiles", detail: "configuration profile store / file signals present (inventory only)"))
        }
        evidence.append(
            Evidence(
                type: "opsec_honesty",
                detail:
                    "Assess does not push Jamf/Intune scripts, does not enroll/unenroll, "
                    + "and does not mutate configuration profiles - channel surface ranking only"
            )
        )
        return evidence
    }

    private static func finding(
        for state: CollectedState,
        signalCount: Int,
        evidence: [Evidence]
    ) -> Finding {
        let enrolled = state.mdm?.enrolled == true
        let vendors = !(state.mdm?.vendorHints.isEmpty ?? true)
        let pppc = state.mdm?.pppcPolicyPresent == true
        let vendorLabel = state.mdm?.vendorHints.isEmpty == true
            ? "enrolled"
            : state.mdm?.vendorHints.prefix(2).joined(separator: ",") ?? "enrolled"
        let severity: Severity
        let title: String
        if enrolled && (vendors || pppc) {
            severity = .medium
            title =
                "MDM management channel: enrolled with vendor/PPPC signals "
                + "(\(vendorLabel))"
        } else if enrolled || signalCount >= 2 {
            severity = .medium
            title = "MDM management channel surface active (\(signalCount) primary signals)"
        } else {
            severity = .low
            title = "MDM management channel indicators present (thin but non-empty)"
        }
        return Finding(id: Self.id, title: title, severity: severity, category: .mdm, resolution: .init(evidence: evidence, attackTechniques: ["T1072", "T1082", "T1484"], remediation: [
                    "Harden MDM/UEM admin roles, break-glass accounts, and enrollment tokens",
                    "Monitor unauthorized profile install / PPPC grants / mass device actions",
                    "Scope management tools least-privilege; audit vendor agent binary integrity",
                    "OPSEC: Rootstock Red never performs Jamf script push or profile mutation in assess",
                ], falsePositiveNotes: "Enrolled fleet machines should fire this vector - it ranks the management "
                    + "channel as an asset/attack surface, opposite of management_gap. Not a finding of misconfig alone."), runtime: .init(confidence: enrolled || vendors ? .medium : .low, dryRunSafe: true, opsecScore: 16, esfExpected: ["OPEN"]))
    }


    private static func describeInt(_ value: Int?) -> String {
        value.map(String.init) ?? "unknown"
    }
}
