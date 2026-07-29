import Foundation
import RootstockCore

/// Credential-path or directory-identity pivot vector - never dumps secrets.
public struct CredOrIdentityPivotVector: Check {
    public static let id = "rootstock.vector.auth.cred_or_identity_pivot"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws
        -> [Finding]
    {
        guard Self.hasPivot(state) else { return [] }
        return [Self.finding(for: state)]
    }

    private static func hasPivot(_ state: CollectedState) -> Bool {
        !state.credPaths.filter(\.exists).isEmpty
            || state.identity?.adBound == true
            || state.identity?.platformSSO == true
    }

    private static func finding(for state: CollectedState) -> Finding {
        let presentation = Self.presentation(for: state)
        return Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .auth, resolution: .init(evidence: evidence(for: state), attackTechniques: attackTechniques(for: state), remediation: [
                "Harden private key / cloud credential file permissions (never world-readable)",
                "Prefer hardware-backed / SSO auth over long-lived key files where possible",
                "Validate AD/Platform SSO join via MDM inventory; review Kerberos ticket lifetime policy",
                "OPSEC: Rootstock Red assess never dumps secrets - path metadata only; avoid security dump-keychain",
            ], falsePositiveNotes: "Path presence ≠ usable secret; AD path heuristics are not live bind proofs"), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 22, esfExpected: ["OPEN"]))
    }

    private static func evidence(for state: CollectedState) -> [Evidence] {
        let existingCreds = state.credPaths.filter(\.exists)
        let identity = state.identity
        let adBound = identity?.adBound == true
        let platformSSO = identity?.platformSSO == true
        let kerberos = identity?.kerberosConfigPresent == true
        var evidence = [
            Evidence(
                type: "pivot_summary",
                detail: "credPathsPresent=\(existingCreds.count) adBound=\(adBound) "
                    + "platformSSO=\(platformSSO) kerberosConfig=\(kerberos) (metadata only - no secret material read)"
            )
        ]
        evidence += existingCreds.prefix(25).map {
            Evidence(
                type: "cred_path", path: $0.path,
                detail: "kind=\($0.kind) exists=true (path presence only)"
            )
        }
        guard let identity else { return evidence }
        evidence.append(
            Evidence(
                type: "identity",
                detail: "adBound=\(identity.adBound.rootstockDescribe) "
                    + "platformSSO=\(identity.platformSSO.rootstockDescribe) kerberosConfigPresent=\(identity.kerberosConfigPresent.rootstockDescribe)"
            ))
        evidence += identity.odConfigPaths.prefix(10).map {
            Evidence(type: "od_path", path: $0, detail: "OD/DirectoryService path")
        }
        evidence += identity.ssoPaths.prefix(10).map {
            Evidence(type: "sso_path", path: $0, detail: "Platform SSO / AppSSO path")
        }
        evidence += identity.notes.prefix(10).map { Evidence(type: "note", detail: $0) }
        return evidence
    }

    private static func attackTechniques(for state: CollectedState) -> [String] {
        let identity = state.identity
        var techniques: Set<String> = []
        if state.credPaths.contains(where: \.exists) {
            techniques.formUnion(["T1552", "T1552.001", "T1003"])
        }
        if identity?.adBound == true || identity?.kerberosConfigPresent == true {
            techniques.formUnion(["T1087.002", "T1558", "T1078.002"])
        }
        if identity?.platformSSO == true { techniques.formUnion(["T1078", "T1550"]) }
        return techniques.isEmpty ? ["T1078"] : techniques.sorted()
    }

    private static func presentation(for state: CollectedState) -> (
        severity: Severity, title: String
    ) {
        let credCount = state.credPaths.filter(\.exists).count
        let adBound = state.identity?.adBound == true
        let platformSSO = state.identity?.platformSSO == true
        if let title = credentialIdentityTitle(
            credentialsPresent: credCount > 0,
            adBound: adBound,
            platformSSO: platformSSO
        ) {
            return (.medium, title)
        }
        let identityLabels = identityLabels(adBound: adBound, platformSSO: platformSSO)
        if !identityLabels.isEmpty {
            return (.low, "Identity pivot: \(identityLabels.joined(separator: " + "))")
        }
        return (.low, "Credential path pivot surface (\(credCount) paths present)")
    }

    private static func credentialIdentityTitle(
        credentialsPresent: Bool, adBound: Bool, platformSSO: Bool
    ) -> String? {
        let titles = [
            "true,true,false": "Auth pivot: credential paths + AD-bound identity surface",
            "true,true,true": "Auth pivot: credential paths + AD-bound identity surface",
            "true,false,true": "Auth pivot: credential paths + Platform SSO identity",
        ]
        return titles["\(credentialsPresent),\(adBound),\(platformSSO)"]
    }

    private static func identityLabels(adBound: Bool, platformSSO: Bool) -> [String] {
        [adBound ? "AD-bound" : nil, platformSSO ? "Platform SSO" : nil].compactMap { $0 }
    }

}
