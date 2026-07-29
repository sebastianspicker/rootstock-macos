import Foundation
import RootstockCore

/// Patch-debt / CVE suggester rule cluster.
///
/// Research basis: compliance version lag; PEASS OS checks.
/// Safety and behavior: ranked multi-rule Findings; suggester language only.
public struct CVEPatchDebtClusterCheck: Check {
    public static let id = "rootstock.check.vuln.cve_patch_debt_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var findings: [Finding] = []
        if let f = Self.majorLag(state: state) { findings.append(f) }
        if let f = Self.remoteWithLag(state: state) { findings.append(f) }
        if let f = Self.missingSUSHints(state: state) { findings.append(f) }
        return findings
    }

    private static func majorLag(state: CollectedState) -> Finding? {
        guard let debt = state.patchDebt, let lag = debt.majorVersionLag, lag >= 1 else {
            return nil
        }
        return Finding(id: "\(id).major_lag", title: "CVE/patch-debt cluster: OS major lag \(lag) (suggester context)", severity: lag >= 2 ? .medium : .low, category: .cve, resolution: .init(evidence: [
                Evidence(
                    type: "os",
                    detail: "version=\(debt.osVersion ?? "?") build=\(debt.osBuild ?? "?") lag=\(lag)"
                ),
                Evidence(
                    type: "honesty",
                    detail: "Not a specific CVE claim; map build to Apple security updates"
                ),
            ], attackTechniques: ["T1082", "T1203"], remediation: [
                "Apply security updates; verify build against Apple security content",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 8, esfExpected: ["OPEN"], osRange: debt.osVersion))
    }

    private static func remoteWithLag(state: CollectedState) -> Finding? {
        guard let debt = state.patchDebt, let lag = debt.majorVersionLag, lag >= 1 else {
            return nil
        }
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        guard remote else { return nil }

        return Finding(id: "\(id).remote_with_lag", title: "CVE/patch-debt cluster: patch lag on remotely accessible host", severity: .medium, category: .cve, resolution: .init(evidence: [
                Evidence(type: "lag", detail: "majorVersionLag=\(lag)"),
                Evidence(
                    type: "remote",
                    detail:
                        "ssh=\((state.network?.remoteLoginSSH).rootstockDescribe) "
                        + "ard=\((state.network?.screenSharingARD).rootstockDescribe)"
                ),
            ], attackTechniques: ["T1082", "T1021", "T1068"], remediation: [
                "Prioritize patching hosts with Remote Login / Screen Sharing",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 10, esfExpected: ["OPEN"]))
    }

    private static func missingSUSHints(state: CollectedState) -> Finding? {
        guard let debt = state.patchDebt else { return nil }
        guard debt.softwareUpdatePlistPresent == false else { return nil }
        // Only interesting with enterprise identity.
        guard state.identity?.adBound == true || state.identity?.platformSSO == true || state.mdm?.enrolled == true
        else { return nil }

        return Finding(id: "\(id).missing_sus_prefs", title: "CVE/patch-debt cluster: Software Update prefs absent on managed/identity host", severity: .low, category: .cve, resolution: .init(evidence: [
                Evidence(type: "sus", detail: "softwareUpdatePlistPresent=false"),
                Evidence(
                    type: "context",
                    detail:
                        "adBound=\((state.identity?.adBound).rootstockDescribe) "
                        + "platformSSO=\((state.identity?.platformSSO).rootstockDescribe) "
                        + "mdm=\((state.mdm?.enrolled).rootstockDescribe)"
                ),
            ], attackTechniques: ["T1082"], remediation: [
                "Confirm update policy via MDM; local SUS plist absence is weak signal only",
            ], falsePositiveNotes: "Managed freezes may hide or relocate update prefs"), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 6, esfExpected: ["OPEN"]))
    }

}
