import Foundation
import RootstockCore

/// ESF × EDR × remote posture cluster.
///
/// Research basis: security product discovery + ESF sensor research.
/// Safety and behavior: multi-rule ranked Findings; never unloads sensors.
public struct ESFEDRPostureClusterCheck: Check {
    public static let id = "rootstock.check.vuln.esf_edr_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var findings: [Finding] = []
        if let f = Self.thinSensorRemote(state: state) { findings.append(f) }
        if let f = Self.sysextWithoutProductCatalog(state: state) { findings.append(f) }
        if let f = Self.frameworkOnlyNoClients(state: state) { findings.append(f) }
        return findings
    }

    private static func thinSensorRemote(state: CollectedState) -> Finding? {
        let present = state.securityProducts.filter(\.present)
        // clientPaths are third-party only; Apple endpointsecurityd must not block this rule.
        let thirdPartyClients = state.esf?.clientPaths.count ?? 0
        let hints = state.esf?.edrHints ?? []
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        guard present.isEmpty && thirdPartyClients == 0 && hints.isEmpty && remote else {
            return nil
        }

        return Finding(id: "\(id).thin_sensor_remote", title: "ESF/EDR cluster: no third-party sensor path hits with remote access enabled", severity: .medium, category: .securityProduct, resolution: .init(evidence: [
                Evidence(
                    type: "edr",
                    detail:
                        "productsPresent=0 thirdPartyClients=0 edrHints=0 "
                        + "(Apple ES infrastructure excluded)"
                ),
                Evidence(
                    type: "remote",
                    detail:
                        "ssh=\((state.network?.remoteLoginSSH).rootstockDescribe) "
                        + "ard=\((state.network?.screenSharingARD).rootstockDescribe)"
                ),
                Evidence(
                    type: "honesty",
                    detail: "Path probes miss many agents - confirm via MDM"
                ),
            ], attackTechniques: ["T1518.001", "T1021", "T1562.001"], remediation: [
                "Deploy ES/EDR clients via MDM on remotely accessible hosts",
                "Disable unused Remote Login / Screen Sharing",
            ], falsePositiveNotes: "Agents may exist as system extensions without catalog hits"), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 14, esfExpected: ["OPEN"]))
    }

    private static func sysextWithoutProductCatalog(state: CollectedState) -> Finding? {
        let sysext =
            state.esf?.systemExtensionCount
            ?? state.systemExtensionPaths.count
        let present = state.securityProducts.filter(\.present)
        guard sysext >= 1 && present.isEmpty else { return nil }

        return Finding(id: "\(id).sysext_without_catalog", title: "ESF/EDR cluster: system extensions present but security product catalog empty", severity: .low, category: .securityProduct, resolution: .init(evidence: [
                Evidence(type: "sysext", detail: "systemExtensionCount≈\(sysext)"),
                Evidence(
                    type: "paths",
                    detail: state.systemExtensionPaths.prefix(8).joined(separator: ",")
                ),
                Evidence(
                    type: "note",
                    detail: "Sygexts may be network filters, drivers, or EDR - inventory by vendor"
                ),
            ], attackTechniques: ["T1518.001", "T1547"], remediation: [
                "Map system extensions to approved vendor inventory",
                "Remove unexpected third-party system extensions",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 12, esfExpected: ["OPEN"]))
    }

    private static func frameworkOnlyNoClients(state: CollectedState) -> Finding? {
        guard let esf = state.esf else { return nil }
        // Stock macOS always has the framework + endpointsecurityd; gap is third-party clients.
        guard esf.frameworkPresent == true, esf.clientPaths.isEmpty, esf.edrHints.isEmpty else {
            return nil
        }
        let highValue =
            state.identity?.adBound == true
            || state.identity?.platformSSO == true
            || state.credPaths.contains(where: \.exists)
        guard highValue else { return nil }

        return Finding(id: "\(id).framework_only_high_value", title: "ESF/EDR cluster: EndpointSecurity framework present without third-party clients on high-value host", severity: .low, category: .securityProduct, resolution: .init(evidence: [
                Evidence(
                    type: "esf",
                    detail: "frameworkPresent=true thirdPartyClients=0 (Apple infra expected)"
                ),
                Evidence(
                    type: "high_value",
                    detail:
                        "adBound=\((state.identity?.adBound).rootstockDescribe) "
                        + "platformSSO=\((state.identity?.platformSSO).rootstockDescribe) "
                        + "credPaths=\(state.credPaths.filter(\.exists).count)"
                ),
            ], attackTechniques: ["T1518.001", "T1082"], remediation: [
                "Verify enterprise sensor enrollment on identity-joined hosts",
            ], falsePositiveNotes: "Framework + endpointsecurityd presence is expected on stock macOS even without third-party EDR"), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 10, esfExpected: ["OPEN"]))
    }

}
