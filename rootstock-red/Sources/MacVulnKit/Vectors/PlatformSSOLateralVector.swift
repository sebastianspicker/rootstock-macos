import Foundation
import RootstockCore

/// Path-to-impact: Platform SSO / Kerberos / AD identity as lateral and ticket-abuse surface.
///
/// Research basis: bifrost Kerberos themes, Orchard AD enum ideas, Empire identity modules.
/// Safety and behavior: filesystem-heuristic only (no ticket dump / ptt); ATT&CK + OPSEC honesty;
/// compounds with remote access and high-value cred paths without secret material.
public struct PlatformSSOLateralVector: Check {
    public static let id = "rootstock.vector.auth.platform_sso_lateral"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard Self.hasIdentitySurface(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }


    private static func hasIdentitySurface(_ state: CollectedState) -> Bool {
        guard let identity = state.identity else { return false }
        return identity.platformSSO == true || identity.adBound == true
            || (identity.kerberosConfigPresent == true && (!identity.ssoPaths.isEmpty || !identity.odConfigPaths.isEmpty))
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        guard let identity = state.identity else { return [] }
        let remote = Self.remoteAccess(state)
        let cloudCredentialCount = Self.cloudCredentialCount(state)
        var evidence: [Evidence] = [Evidence(type: "identity_lateral", detail: "platformSSO=\(identity.platformSSO.rootstockDescribe) " + "adBound=\(identity.adBound.rootstockDescribe) " + "kerberosConfig=\(identity.kerberosConfigPresent.rootstockDescribe) " + "(no tickets dumped; no keytab read)")]
        for path in identity.ssoPaths.prefix(12) { evidence.append(Evidence(type: "sso_path", path: path, detail: "Platform SSO / AppSSO support path")) }
        for path in identity.odConfigPaths.prefix(12) { evidence.append(Evidence(type: "od_path", path: path, detail: "Open Directory / AD config path")) }
        for note in identity.notes.prefix(10) { evidence.append(Evidence(type: "note", detail: note)) }
        if remote { evidence.append(Evidence(type: "compound_remote", detail: "Remote access enabled - identity plane increases lateral value of this host")) }
        if cloudCredentialCount > 0 { evidence.append(Evidence(type: "compound_cred_paths", detail: "cloud/ssh path presence=\(cloudCredentialCount) (metadata only)")) }
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let identity = state.identity!
        let presentation = findingPresentation(
            platformSSO: identity.platformSSO == true,
            adBound: identity.adBound == true,
            kerberos: identity.kerberosConfigPresent == true,
            amplified: remoteAccess(state) || cloudCredentialCount(state) > 0
        )
        return Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .auth, resolution: .init(evidence: evidence, attackTechniques: ["T1078.002", "T1558", "T1550.003", "T1087.002", "T1550"], remediation: ["Validate Platform SSO / AD join via MDM inventory; remove stale directory bindings", "Prefer short-lived SSO tokens over long-lived key files beside identity join", "Monitor anomalous Kerberos ticket requests from endpoints (SOC), not local keytab dumps", "OPSEC: Rootstock Red never dumps tickets or performs pass-the-ticket - assess only"], falsePositiveNotes: "Path heuristics are not live SSO/AD bind proofs. Kerberos conf alone is common on " + "developer images without enterprise join."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 20, esfExpected: ["OPEN"]))
    }


    private static func findingPresentation(
        platformSSO: Bool,
        adBound: Bool,
        kerberos: Bool,
        amplified: Bool
    ) -> (title: String, severity: Severity) {
        if platformSSO && adBound {
            return ("Identity lateral vector: Platform SSO + AD-bound posture", .medium)
        }
        if platformSSO {
            return ("Identity lateral vector: Platform SSO surface", amplified ? .medium : .low)
        }
        if adBound && kerberos {
            return ("Identity lateral vector: AD-bound + Kerberos config surface", .medium)
        }
        return ("Identity lateral vector: directory/SSO configuration surface", .low)
    }

    private static func remoteAccess(_ state: CollectedState) -> Bool {
        state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
    }

    private static func cloudCredentialCount(_ state: CollectedState) -> Int {
        state.credPaths.filter { $0.exists && ["aws", "gcp", "azure", "ssh"].contains($0.kind) }.count
    }

}
