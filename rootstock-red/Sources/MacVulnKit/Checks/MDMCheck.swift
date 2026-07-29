/// Cluster/check: MDMCheck - multi-signal posture ranking for assess pipeline.
import Foundation
import RootstockCore

public struct MDMHintsCheck: Check {
    public static let id = "rootstock.check.mdm.vendor_hints"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let mdm = state.mdm else { return [] }
        if mdm.vendorHints.isEmpty {
            return [
                Finding(id: "\(Self.id).none", title: "No common MDM vendor paths detected", severity: .low, category: .mdm, resolution: .init(evidence: mdm.notes.prefix(15).map { Evidence(type: "note", detail: $0) }, attackTechniques: ["T1082"], remediation: ["Confirm management state via profiles / ABM inventory"]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 5)),
            ]
        }
        return [
            Finding(id: Self.id, title: "MDM / management vendor hints: \(mdm.vendorHints.joined(separator: ", "))", severity: .info, category: .mdm, resolution: .init(evidence: mdm.vendorHints.map { Evidence(type: "vendor", detail: $0) }
                    + mdm.notes.prefix(10).map { Evidence(type: "note", detail: $0) }, attackTechniques: ["T1082"], remediation: ["Correlate vendor agents with configuration profiles and PPPC payloads"]), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 8)),
        ]
    }
}

/// Managed preferences + profile-store posture (complements vendor path hints).
public struct MDMProfilesCheck: Check {
    public static let id = "rootstock.check.mdm.profiles"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let mdm = state.mdm else { return [] }
        return [Self.finding(for: mdm)]
    }


    private struct Presentation { let title: String; let severity: Severity; let confidence: Confidence }

    private static func finding(for mdm: MDMState) -> Finding {
        let presentation = presentation(for: mdm)
        return Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .mdm, resolution: .init(evidence: evidence(for: mdm), attackTechniques: ["T1082", "T1562"], remediation: ["Inventory configuration profiles via MDM console / ABM", "Review PPPC payloads for over-broad TCC grants"], falsePositiveNotes: "Profile store may be unreadable without root; managed prefs can exist without full MDM enrollment"), runtime: .init(confidence: presentation.confidence, dryRunSafe: true, opsecScore: 7, esfExpected: []))
    }

    private static func presentation(for mdm: MDMState) -> Presentation {
        let hasProfiles = (mdm.profileFileCount ?? 0) > 0 || !mdm.managedPreferenceNames.isEmpty || mdm.pppcPolicyPresent == true || mdm.enrolled == true
        if mdm.pppcPolicyPresent == true { return Presentation(title: "MDM profiles / PPPC policy payloads present", severity: .info, confidence: .medium) }
        if hasProfiles { return Presentation(title: "MDM profile store / managed preferences inventory (\(mdm.managedPreferenceNames.count) managed prefs\(mdm.profileFileCount.map { ", ~\($0) profile files" } ?? ""))", severity: .info, confidence: profileConfidence(for: mdm)) }
        return Presentation(title: "No managed preferences or profile-store files visible", severity: .low, confidence: .low)
    }

    private static func profileConfidence(for mdm: MDMState) -> Confidence {
        mdm.profileStoreReadable == true || !mdm.managedPreferenceNames.isEmpty ? .medium : .low
    }

    private static func evidence(for mdm: MDMState) -> [Evidence] {
        let profileFileCount = mdm.profileFileCount.map { String($0) } ?? "unknown"
        let summary = Evidence(type: "mdm", detail: "enrolled=\(mdm.enrolled.rootstockDescribe) profileStoreReadable=\(mdm.profileStoreReadable.rootstockDescribe) profileFileCount=\(profileFileCount) pppcPolicyPresent=\(mdm.pppcPolicyPresent.rootstockDescribe)")
        let preferences = mdm.managedPreferenceNames.prefix(40).map { Evidence(type: "managed_pref", path: "/Library/Managed Preferences/\($0)", detail: $0) }
        return [summary] + preferences + mdm.notes.prefix(20).map { Evidence(type: "note", detail: $0) }
    }

}
