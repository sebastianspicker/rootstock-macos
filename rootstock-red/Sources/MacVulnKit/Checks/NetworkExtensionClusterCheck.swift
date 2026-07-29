import Foundation
import RootstockCore

/// NetworkExtension × remote × filter posture cluster.
///
/// Research basis: NE/content-filter research; firewall product catalogs.
/// Safety and behavior: multi-rule ranked Findings; never modifies NE configuration.
public struct NetworkExtensionClusterCheck: Check {
    public static let id = "rootstock.check.vuln.network_extension_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var findings: [Finding] = []
        if let f = Self.noFilterWithRemote(state: state) { findings.append(f) }
        if let f = Self.vpnOnlyNoContentFilter(state: state) { findings.append(f) }
        if let f = Self.frameworkWithoutApps(state: state) { findings.append(f) }
        return findings
    }

    /// Count enterprise content-filter hints only (stock pf/ALF must not count as coverage).
    private static func enterpriseFilterCount(_ state: CollectedState) -> Int {
        (state.networkExtension?.contentFilterHints ?? []).filter { hint in
            let lower = hint.lowercased()
            return !lower.contains("pf_conf")
                && !lower.contains("pf_anchors")
                && !lower.contains("/etc/pf.")
                && !lower.contains("application_firewall")
                && !lower.contains("com.apple.alf")
        }.count
    }

    private static func noFilterWithRemote(state: CollectedState) -> Finding? {
        let filters = enterpriseFilterCount(state)
        let apps = state.networkExtension?.neAppPaths.count ?? 0
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        guard filters == 0 && apps == 0 && remote else { return nil }

        return Finding(id: "\(id).no_filter_with_remote", title: "NE cluster: no content-filter inventory with remote access enabled", severity: .medium, category: .network, resolution: .init(evidence: [
                Evidence(type: "filter", detail: "contentFilterHints=0 neApps=0"),
                Evidence(
                    type: "remote",
                    detail:
                        "ssh=\((state.network?.remoteLoginSSH).rootstockDescribe) "
                        + "ard=\((state.network?.screenSharingARD).rootstockDescribe)"
                ),
            ], attackTechniques: ["T1562.004", "T1021"], remediation: [
                "Deploy content-filter / host firewall agents on SSH/ARD-enabled hosts",
                "Disable unused remote services",
            ], falsePositiveNotes: "Path probes miss many commercial filters"), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 14, esfExpected: ["OPEN"]))
    }

    private static func vpnOnlyNoContentFilter(state: CollectedState) -> Finding? {
        let vpn = state.networkExtension?.vpnConfigPaths.count ?? 0
        let filters = enterpriseFilterCount(state)
        guard vpn >= 1 && filters == 0 else { return nil }

        return Finding(id: "\(id).vpn_only_no_content_filter", title: "NE cluster: VPN config paths present without content-filter hints", severity: .low, category: .network, resolution: .init(evidence: [
                Evidence(type: "vpn", detail: "vpnConfigPaths=\(vpn)"),
                Evidence(type: "filter", detail: "contentFilterHints=0"),
                Evidence(
                    type: "paths",
                    detail: (state.networkExtension?.vpnConfigPaths ?? []).prefix(6).joined(separator: ",")
                ),
            ], attackTechniques: ["T1090", "T1562.004"], remediation: [
                "Pair corporate VPN with approved content-filter / DNS security where policy requires",
                "Inventory packet-tunnel providers for shadow IT tunnels",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 12, esfExpected: ["OPEN"]))
    }

    private static func frameworkWithoutApps(state: CollectedState) -> Finding? {
        guard state.networkExtension?.frameworkPresent == true else { return nil }
        let apps = state.networkExtension?.neAppPaths.count ?? 0
        let filters = enterpriseFilterCount(state)
        let highValue =
            state.identity?.adBound == true
            || state.identity?.platformSSO == true
            || state.credPaths.contains(where: \.exists)
        guard apps == 0 && filters == 0 && highValue else { return nil }

        return Finding(id: "\(id).framework_without_apps", title: "NE cluster: NetworkExtension framework present without filter apps on high-value host", severity: .low, category: .network, resolution: .init(evidence: [
                Evidence(type: "ne", detail: "frameworkPresent=true neApps=0 contentFilterHints=0"),
                Evidence(
                    type: "high_value",
                    detail:
                        "adBound=\((state.identity?.adBound).rootstockDescribe) "
                        + "platformSSO=\((state.identity?.platformSSO).rootstockDescribe)"
                ),
            ], attackTechniques: ["T1518", "T1082"], remediation: [
                "Confirm enterprise network-filter enrollment on identity-joined hosts",
            ], falsePositiveNotes: "Framework presence is expected on modern macOS even without third-party filters"), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 10, esfExpected: ["OPEN"]))
    }

}
