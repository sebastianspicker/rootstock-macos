import Foundation
import RootstockCore

/// Second vuln/misconfig rule cluster (beyond PEASS path cluster): identity × EDR × remote posture.
///
/// Research basis: PEASS prioritization + bifrost/Empire identity themes + security-product discovery.
/// Safety and behavior: multi-rule API-first cluster with ranked Findings; no ticket dump, no shell storms.
public struct IdentityEDRClusterCheck: Check {
    public static let id = "rootstock.check.vuln.identity_edr_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var findings: [Finding] = []
        if let f = Self.ssoWithoutHardening(state: state) {
            findings.append(f)
        }
        if let f = Self.noEDRWithRemote(state: state) {
            findings.append(f)
        }
        if let f = Self.adKerberosHighValue(state: state) {
            findings.append(f)
        }
        return findings
    }

    // MARK: - Rules

    /// Platform SSO / AD identity without PPPC or MDM hardening signals.
    private static func ssoWithoutHardening(state: CollectedState) -> Finding? {
        guard let identity = state.identity else { return nil }
        let idOn = identity.platformSSO == true || identity.adBound == true
        guard idOn else { return nil }

        let mdm = state.mdm
        let thinMDM =
            mdm == nil
            || mdm?.enrolled == false
            || (mdm?.pppcPolicyPresent != true && (mdm?.vendorHints.isEmpty ?? true))

        guard thinMDM else { return nil }

        var evidence: [Evidence] = [
            Evidence(
                type: "identity",
                detail:
                    "platformSSO=\(identity.platformSSO.rootstockDescribe) adBound=\(identity.adBound.rootstockDescribe)"
            ),
            Evidence(
                type: "mdm",
                detail:
                    "enrolled=\((mdm?.enrolled).rootstockDescribe) pppc=\((mdm?.pppcPolicyPresent).rootstockDescribe) "
                    + "vendors=\(mdm?.vendorHints.count ?? 0)"
            ),
        ]
        for path in identity.ssoPaths.prefix(8) {
            evidence.append(Evidence(type: "sso_path", path: path, detail: "SSO path"))
        }

        return Finding(id: "\(id).sso_without_hardening", title: "Identity/EDR cluster: directory/SSO join without strong MDM/PPPC signals", severity: .medium, category: .auth, resolution: .init(evidence: evidence, attackTechniques: ["T1078.002", "T1550", "T1082"], remediation: [
                "Enroll identity-joined hosts; deploy PPPC for approved tools only",
                "Correlate Platform SSO/AD with MDM compliance baselines",
            ], falsePositiveNotes: "Path heuristics may miss some UEM products"), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 16, esfExpected: ["OPEN"]))
    }

    /// No security-product path hits while remote access is indicated.
    private static func noEDRWithRemote(state: CollectedState) -> Finding? {
        let present = state.securityProducts.filter(\.present)
        // Fire when products list empty or all absent.
        let noEDR = present.isEmpty
        guard noEDR else { return nil }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        guard remote else { return nil }

        return Finding(id: "\(id).no_edr_with_remote", title: "Identity/EDR cluster: no EDR path hits with remote access enabled", severity: .medium, category: .securityProduct, resolution: .init(evidence: [
                Evidence(
                    type: "edr",
                    detail: "securityProductsPresent=0 catalog=\(state.securityProducts.count)"
                ),
                Evidence(
                    type: "remote",
                    detail:
                        "ssh=\((state.network?.remoteLoginSSH).rootstockDescribe) "
                        + "ard=\((state.network?.screenSharingARD).rootstockDescribe)"
                ),
                Evidence(
                    type: "honesty",
                    detail: "Path probes miss many agents - confirm via MDM before treating as fact"
                ),
            ], attackTechniques: ["T1518.001", "T1021", "T1562.001"], remediation: [
                "Prioritize EDR coverage on remotely accessible hosts",
                "Disable unused Remote Login / Screen Sharing",
            ], falsePositiveNotes: "EDR may exist as system extension without catalog path hits"), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 14, esfExpected: ["OPEN"]))
    }

    /// AD + Kerberos with high-value local cred/browser surface.
    private static func adKerberosHighValue(state: CollectedState) -> Finding? {
        guard let identity = state.identity else { return nil }
        let adOrKrb = identity.adBound == true || identity.kerberosConfigPresent == true
        guard adOrKrb else { return nil }

        let highValue =
            state.credPaths.contains(where: \.exists)
            || state.browserMeta.contains(where: \.exists)
        guard highValue else { return nil }

        return Finding(id: "\(id).ad_kerberos_high_value", title: "Identity/EDR cluster: AD/Kerberos signals with local high-value data paths", severity: .medium, category: .auth, resolution: .init(evidence: [
                Evidence(
                    type: "identity",
                    detail:
                        "adBound=\(identity.adBound.rootstockDescribe) "
                        + "kerberos=\(identity.kerberosConfigPresent.rootstockDescribe)"
                ),
                Evidence(
                    type: "high_value",
                    detail:
                        "credPathsPresent=\(state.credPaths.filter(\.exists).count) "
                        + "browserMetaPresent=\(state.browserMeta.filter(\.exists).count) "
                        + "(metadata only - no secret dump)"
                ),
            ], attackTechniques: ["T1558", "T1552", "T1005", "T1078.002"], remediation: [
                "Harden local secret file permissions; prefer SSO over long-lived keys",
                "Do not dump tickets from assess tooling - use SOC telemetry for abuse detection",
            ], falsePositiveNotes: "Developer machines often combine Kerberos conf with cloud CLI keys"), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 18, esfExpected: ["OPEN"]))
    }

}
