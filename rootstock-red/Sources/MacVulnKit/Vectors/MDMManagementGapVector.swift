import Foundation
import RootstockCore

/// Path-to-impact: missing or weak MDM/PPPC posture when the host still has attack surface.
///
/// Requires supporting remote-access, weak-protection, credential, or browser
/// path signals before reporting a finding.
public struct MDMManagementGapVector: Check {
    public static let id = "rootstock.vector.mdm.management_gap"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws
        -> [Finding]
    {
        guard let mdm = state.mdm else { return [] }
        guard Self.isUnmanaged(mdm) else { return [] }
        let signals = Self.supportingSignals(state)
        guard signals.any else { return [] }
        return [Self.finding(mdm: mdm, signals: signals)]
    }

    private struct SupportingSignals {
        let remote: Bool
        let weakProtections: Bool
        let highValue: Bool
        let inject: Bool

        var any: Bool { [remote, weakProtections, highValue, inject].contains(true) }
    }

    private static func isUnmanaged(_ mdm: MDMState) -> Bool {
        let noVendors = mdm.vendorHints.isEmpty
        let noProfiles = (mdm.profileFileCount ?? 0) == 0 && mdm.managedPreferenceNames.isEmpty
        let noPPPC = mdm.pppcPolicyPresent != true
        return [
            mdm.enrolled == false,
            mdm.enrolled == nil && noVendors && noProfiles,
            noVendors && noPPPC && noProfiles,
        ].contains(true)
    }

    private static func supportingSignals(_ state: CollectedState) -> SupportingSignals {
        SupportingSignals(
            remote: [
                state.network?.remoteLoginSSH, state.network?.screenSharingARD,
                state.network?.fileSharingSMB,
            ].contains(true),
            weakProtections: [
                state.protections?.sipEnabled == false,
                state.protections?.gatekeeperEnabled == false,
            ].contains(true),
            highValue: [
                state.credPaths.contains(where: \.exists),
                state.browserMeta.contains(where: \.exists),
                state.identity?.adBound == true,
            ].contains(true),
            inject: state.injectabilityHits.contains { !$0.riskFlags.isEmpty }
        )
    }

    private static func finding(mdm: MDMState, signals: SupportingSignals) -> Finding {
        let presentation = Self.presentation(mdm: mdm, signals: signals)
        return Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .mdm, resolution: .init(evidence: evidence(mdm: mdm, signals: signals), attackTechniques: ["T1082", "T1562", "T1078", "T1204"], remediation: [
                "Enroll unmanaged high-value hosts into MDM/ABM where policy requires it",
                "Deploy PPPC / TCC configuration-profile policy for approved tools only",
                "Disable unnecessary Remote Login / Screen Sharing when not managed",
                "OPSEC: path heuristics for MDM are quiet; do not run jamf recon storms from assess",
            ], falsePositiveNotes: "Personal Macs legitimately lack MDM. Path/vendor heuristics miss some UEM products; "
                + "confirm with profiles list / business inventory before treating as critical."), runtime: .init(confidence: mdm.enrolled == false ? .medium : .low, dryRunSafe: true, opsecScore: 14, esfExpected: ["OPEN"]))
    }

    private static func evidence(mdm: MDMState, signals: SupportingSignals) -> [Evidence] {
        var evidence = [
            Evidence(
                type: "mdm_summary",
                detail:
                    "enrolled=\(mdm.enrolled.rootstockDescribe) vendors=\(mdm.vendorHints.count) "
                    + "managedPrefs=\(mdm.managedPreferenceNames.count) profileFiles=\(Self.describeInt(mdm.profileFileCount)) "
                    + "pppcPolicyPresent=\(mdm.pppcPolicyPresent.rootstockDescribe)")
        ]
        evidence += mdm.notes.prefix(12).map { Evidence(type: "note", detail: $0) }
        evidence += supportEvidence(signals)
        return evidence
    }

    private static func supportEvidence(_ signals: SupportingSignals) -> [Evidence] {
        [
            signals.remote
                ? Evidence(
                    type: "supporting_remote",
                    detail: "remote access / sharing posture elevated without strong MDM signals")
                : nil,
            signals.weakProtections
                ? Evidence(
                    type: "supporting_protections",
                    detail: "SIP/Gatekeeper weak while management gap present"
                ) : nil,
            signals.highValue
                ? Evidence(
                    type: "supporting_high_value",
                    detail:
                        "cred/browser/identity high-value surface without PPPC/MDM hardening signal"
                )
                : nil,
            signals.inject
                ? Evidence(
                    type: "supporting_inject",
                    detail: "injectability flags present on unmanaged-like host")
                : nil,
        ].compactMap { $0 }
    }

    private static func presentation(mdm: MDMState, signals: SupportingSignals) -> (
        severity: Severity, title: String
    ) {
        if mdm.enrolled == false && [signals.remote, signals.weakProtections].contains(true) {
            return (.medium, "MDM management gap: not enrolled with elevated host attack surface")
        }
        if mdm.pppcPolicyPresent != true && signals.highValue {
            return (.medium, "MDM/PPPC gap: no PPPC policy signal with high-value data surface")
        }
        return (.low, "MDM posture thin or absent with supporting path-to-impact signals")
    }

    private static func describeInt(_ value: Int?) -> String {
        value.map(String.init) ?? "unknown"
    }
}
