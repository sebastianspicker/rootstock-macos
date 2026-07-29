import Foundation
import RootstockCore

/// Sandbox × notarization × quarantine/GK trust-delivery depth cluster (Wave-7).
///
/// Research basis: delivery-trust research across GK/notarization/entitlements.
/// Safety and behavior: multi-rule ranked Findings; no bypass recipes.
public struct TrustDeliveryDepthClusterCheck: Check {
    public static let id = "rootstock.check.vuln.trust_delivery_depth_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var findings: [Finding] = []
        if let f = Self.thickClientWithWeakCodesign(state: state) { findings.append(f) }
        if let f = Self.notarizationWithGKGap(state: state) { findings.append(f) }
        if let f = Self.deliveryArtifactCompound(state: state) { findings.append(f) }
        return findings
    }

    private static func thickClientWithWeakCodesign(state: CollectedState) -> Finding? {
        let apps = state.appSandboxEntitlements?.appSamples.count ?? 0
        let risk = state.appSandboxEntitlements?.unsandboxedRiskPaths.count ?? 0
        let weak = state.codesignSamples.contains {
            $0.signed == false || $0.getTaskAllow == true || $0.hardenedRuntime == false
        }
        let inject = state.injectabilityHits.contains { !$0.riskFlags.isEmpty }
        guard (apps > 0 || risk > 0) && (weak || inject) else { return nil }

        return Finding(id: "\(id).thick_client_weak_codesign", title: "Trust-delivery cluster: thick-client surface with weak codesign/inject compound", severity: (risk > 0 && inject) ? .medium : .low, category: .sandbox, resolution: .init(evidence: [
                Evidence(
                    type: "sandbox",
                    detail: "appSamples=\(apps) riskPaths=\(risk) weakCodesign=\(weak) inject=\(inject)"
                ),
            ], attackTechniques: ["T1553", "T1055"], remediation: [
                "Ship production clients with Hardened Runtime and without get-task-allow",
                "Prefer sandboxed distribution channels for enterprise software",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 18, esfExpected: ["OPEN"]))
    }

    private static func notarizationWithGKGap(state: CollectedState) -> Finding? {
        let tools = state.notarizationStapling?.toolingPaths.count ?? 0
        let delivery = state.notarizationStapling?.unstapledOrAdHocHints.count ?? 0
        let note = state.collectorNotes["collect.notarization_stapling"] != nil
        let gkOff = state.protections?.gatekeeperEnabled == false
        guard (tools > 0 || delivery > 0 || note) && (gkOff || delivery > 0) else { return nil }

        return Finding(id: "\(id).notarization_gk_gap", title: gkOff
                ? "Trust-delivery cluster: notarization surface with Gatekeeper disabled"
                : "Trust-delivery cluster: delivery artifacts without strong notarization posture signals", severity: gkOff ? .medium : .low, category: .codesign, resolution: .init(evidence: [
                Evidence(
                    type: "notarization",
                    detail:
                        "tools=\(tools) deliveryHints=\(delivery) "
                        + "gatekeeperEnabled=\((state.protections?.gatekeeperEnabled).rootstockDescribe)"
                ),
            ], attackTechniques: ["T1553.001", "T1204.002"], remediation: [
                "Re-enable Gatekeeper; require notarized software on managed fleets",
                "Clear unexpected installer artifacts from Downloads on high-value hosts",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 16, esfExpected: ["OPEN"]))
    }

    private static func deliveryArtifactCompound(state: CollectedState) -> Finding? {
        let delivery = state.notarizationStapling?.unstapledOrAdHocHints.count ?? 0
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let unsigned = state.codesignSamples.filter { $0.signed == false }.count
        guard delivery > 0 && (remote || unsigned > 0) else { return nil }

        return Finding(id: "\(id).delivery_remote_compound", title: "Trust-delivery cluster: delivery artifacts compound with remote access or unsigned samples", severity: remote && unsigned > 0 ? .medium : .low, category: .codesign, resolution: .init(evidence: [
                Evidence(
                    type: "compound",
                    detail: "deliveryHints=\(delivery) unsigned=\(unsigned) remote=\(remote)"
                ),
            ], attackTechniques: ["T1204.002", "T1021"], remediation: [
                "Harden remote access on hosts used for software staging",
                "Enforce code-signing policy for tools installed outside MDM",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 17, esfExpected: ["OPEN"]))
    }

}
