import Foundation
import RootstockCore

/// Auth rights × developer toolchain privilege cluster.
///
/// Research basis: auth.db / PackageKit / Xcode dual-use research.
/// Safety and behavior: multi-rule ranked Findings; never edits auth.db or runs compilers.
public struct AuthDevPrivilegeClusterCheck: Check {
    public static let id = "rootstock.check.vuln.auth_dev_privilege_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var findings: [Finding] = []
        if let f = Self.authdbPackageKit(state: state) { findings.append(f) }
        if let f = Self.toolchainHighValue(state: state) { findings.append(f) }
        if let f = Self.dualUseWithInject(state: state) { findings.append(f) }
        return findings
    }

    private static func authdbPackageKit(state: CollectedState) -> Finding? {
        let auth = state.authRights
        let surface =
            auth?.authDbPresent == true
            || !(auth?.packageKitPaths.isEmpty ?? true)
            || !(auth?.authorizationPlistPaths.isEmpty ?? true)
            || state.collectorNotes["collect.auth_rights"] != nil
        guard surface else { return nil }

        return Finding(id: "\(id).authdb_packagekit_surface", title: "Auth/dev cluster: authorization / PackageKit privilege surface observed", severity: state.protections?.sipEnabled == false ? .medium : .low, category: .auth, resolution: .init(evidence: [
                Evidence(
                    type: "auth",
                    detail:
                        "authDb=\((auth?.authDbPresent).rootstockDescribe) "
                        + "packageKit=\(auth?.packageKitPaths.count ?? 0) "
                        + "authPlists=\(auth?.authorizationPlistPaths.count ?? 0)"
                ),
                Evidence(
                    type: "honesty",
                    detail: "Stock macOS includes auth.db and PackageKit - surface ≠ exploit"
                ),
            ], attackTechniques: ["T1548", "T1068"], remediation: [
                "Monitor installer/authd activity on high-value hosts",
                "Keep SIP enabled; control custom authorization rights centrally",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 16, esfExpected: ["OPEN"]))
    }

    private static func toolchainHighValue(state: CollectedState) -> Finding? {
        let dev = state.developerToolchain
        let present =
            dev?.xcodePresent == true
            || dev?.commandLineToolsPresent == true
            || (dev?.dualUseBinaries.count ?? 0) >= 2
            || state.collectorNotes["collect.developer_toolchain"] != nil
            || state.collectorNotes["dev.toolchain_present"] != nil
        let highValue =
            state.identity?.adBound == true
            || state.identity?.platformSSO == true
            || state.credPaths.contains(where: \.exists)
        guard present && highValue else { return nil }

        return Finding(id: "\(id).toolchain_on_high_value_host", title: "Auth/dev cluster: developer toolchain on high-value / identity-joined host", severity: .low, category: .codesign, resolution: .init(evidence: [
                Evidence(
                    type: "toolchain",
                    detail:
                        "xcode=\((dev?.xcodePresent).rootstockDescribe) clt=\((dev?.commandLineToolsPresent).rootstockDescribe) "
                        + "dualUse=\(dev?.dualUseBinaries.count ?? 0)"
                ),
                Evidence(
                    type: "high_value",
                    detail:
                        "adBound=\((state.identity?.adBound).rootstockDescribe) "
                        + "platformSSO=\((state.identity?.platformSSO).rootstockDescribe) "
                        + "credPaths=\(state.credPaths.filter(\.exists).count)"
                ),
            ], attackTechniques: ["T1127", "T1059", "T1588.002"], remediation: [
                "Scope Xcode/CLT to approved developer roles",
                "Increase process telemetry for codesign/clang/lldb on SSO-joined endpoints",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 18, esfExpected: ["EXEC"]))
    }

    private static func dualUseWithInject(state: CollectedState) -> Finding? {
        let dual = state.developerToolchain?.dualUseBinaries.count ?? 0
        let toolPresent =
            dual >= 1
            || state.developerToolchain?.xcodePresent == true
            || state.collectorNotes["dev.toolchain_present"] != nil
        let inject = state.injectabilityHits.contains {
            $0.getTaskAllow == true || $0.hardenedRuntime == false || !$0.riskFlags.isEmpty
        }
        guard toolPresent && inject else { return nil }

        return Finding(id: "\(id).dual_use_with_inject", title: "Auth/dev cluster: dual-use toolchain compounds with injectability signals", severity: .medium, category: .codesign, resolution: .init(evidence: [
                Evidence(type: "dual_use", detail: "dualUseBinaries=\(dual)"),
                Evidence(
                    type: "inject",
                    detail: "injectabilityHits=\(state.injectabilityHits.count)"
                ),
            ], attackTechniques: ["T1055", "T1127", "T1553.002"], remediation: [
                "Remove get-task-allow from non-debug production builds",
                "Constrain who can run local debug toolchains against privileged apps",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 24, esfExpected: ["EXEC", "OPEN"]))
    }

}
