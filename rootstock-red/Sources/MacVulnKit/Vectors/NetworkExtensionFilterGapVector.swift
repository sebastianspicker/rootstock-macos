import Foundation
import RootstockCore

/// Path-to-impact: thin NetworkExtension / VPN / content-filter inventory with remote or high-value surface.
///
/// Research basis: NE firewall research; content-filter bypass classes; vendor filter catalogs.
/// Safety and behavior: typed NE posture compound with remote/identity; never modifies NE config.
public struct NetworkExtensionFilterGapVector: Check {
    public static let id = "rootstock.vector.ne.vpn_content_filter_gap"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard Self.hasThinFilter(state), Self.hasPathToImpact(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }


    private static func hasThinFilter(_ state: CollectedState) -> Bool {
        let ne = state.networkExtension
        return (ne?.contentFilterHints ?? []).filter(isEnterpriseFilterHint).isEmpty
            && (ne?.neAppPaths.isEmpty ?? true)
    }

    private static func hasPathToImpact(_ state: CollectedState) -> Bool {
        let vpnPaths = state.networkExtension?.vpnConfigPaths.count ?? 0
        return remoteAccess(state)
            || hasHighValueSurface(state)
            || isGapNoted(in: state.collectorNotes)
            || vpnPaths > 0
    }

    private static func remoteAccess(_ state: CollectedState) -> Bool {
        state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
    }

    private static func hasHighValueSurface(_ state: CollectedState) -> Bool {
        state.credPaths.contains(where: \.exists)
            || state.identity?.platformSSO == true
            || state.identity?.adBound == true
    }


    private static func isEnterpriseFilterHint(_ hint: String) -> Bool {
        let lower = hint.lowercased()
        return !lower.contains("pf_conf")
            && !lower.contains("pf_anchors")
            && !lower.contains("/etc/pf.")
            && !lower.contains("application_firewall")
            && !lower.contains("com.apple.alf")
    }

    private static func isGapNoted(in notes: [String: String]) -> Bool {
        notes["ne.filter_gap"] != nil
            || notes["collect.network_extension"]?.contains("contentFilter=0") == true
            || notes["collect.network_extension"]?.contains("filters=0") == true
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let ne = state.networkExtension
        let filterHints = (ne?.contentFilterHints ?? []).filter(Self.isEnterpriseFilterHint).count
        let vpnPaths = ne?.vpnConfigPaths.count ?? 0
        let neApps = ne?.neAppPaths.count ?? 0
        let remote = Self.remoteAccess(state)
        let highValue = Self.hasHighValueSurface(state)
        var evidence: [Evidence] = [
            Evidence(
                type: "ne_summary",
                detail:
                    "framework=\((ne?.frameworkPresent).rootstockDescribe) "
                    + "vpnConfigs=\(vpnPaths) contentFilterHints=\(filterHints) "
                    + "packetTunnel=\(ne?.packetTunnelHints.count ?? 0) neApps=\(neApps)"
            ),
        ]
        if let ne {
            for note in ne.notes.prefix(10) {
                evidence.append(Evidence(type: "ne_note", detail: note))
            }
            for path in (ne.vpnConfigPaths + ne.neAppPaths).prefix(8) {
                evidence.append(Evidence(type: "ne_path", path: path, detail: "NE-related path"))
            }
        }
        appendCompoundEvidence(for: state, remote: remote, highValue: highValue, to: &evidence)
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Path probes miss MDM-deployed filters and in-kernel pf rules. "
                    + "Thin inventory ≠ proof that network filtering is absent."
            )
        )
        return evidence
    }

    private func appendCompoundEvidence(
        for state: CollectedState,
        remote: Bool,
        highValue: Bool,
        to evidence: inout [Evidence]
    ) {
        if remote {
            evidence.append(
                Evidence(
                    type: "compound_remote",
                    detail:
                        "ssh=\((state.network?.remoteLoginSSH).rootstockDescribe) "
                        + "ard=\((state.network?.screenSharingARD).rootstockDescribe)"
                )
            )
        }
        if highValue {
            evidence.append(
                Evidence(
                    type: "compound_high_value",
                    detail:
                        "credPaths=\(state.credPaths.filter(\.exists).count) "
                        + "platformSSO=\((state.identity?.platformSSO).rootstockDescribe) "
                        + "adBound=\((state.identity?.adBound).rootstockDescribe)"
                )
            )
        }
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let remote = remoteAccess(state)
        let severity: Severity = remote ? .medium : .low
        return Finding(id: Self.id, title: remote
                    ? "NetworkExtension gap: thin content-filter inventory with remote access enabled"
                    : "NetworkExtension / VPN / content-filter posture gap candidate", severity: severity, category: .network, resolution: .init(evidence: evidence, attackTechniques: ["T1562.004", "T1090", "T1021"], remediation: [
                    "Deploy approved content-filter / NE clients via MDM on remotely accessible hosts",
                    "Inventory VPN and packet-tunnel providers against corporate allow-list",
                    "Purple: pair assess findings with expected NE/filter telemetry events",
                    "OPSEC: Rootstock Red never modifies NetworkExtension configuration",
                ], falsePositiveNotes: "Many enterprise filters install as system extensions under vendor paths not in the probe catalog."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 14, esfExpected: ["OPEN", "NW_CONNECTION"]))
    }

}
