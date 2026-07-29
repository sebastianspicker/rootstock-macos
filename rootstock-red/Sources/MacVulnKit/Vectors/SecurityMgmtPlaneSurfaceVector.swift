import Foundation
import RootstockCore

/// Path-to-impact: security-product management-plane / privileged-XPC unload class.
///
/// Research basis: XM Cyber–class security-tool management-plane research.
/// Safety and behavior: path-only posture; never unloads system extensions or stops EDR.
public struct SecurityMgmtPlaneSurfaceVector: Check {
    public static let id = "rootstock.vector.edr.security_mgmt_plane_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard hasSurface(state), hasInventory(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func hasSurface(_ state: CollectedState) -> Bool {
        let mgmt = state.securityMgmtPlane
        let cli = mgmt?.managementCLIPaths.count ?? 0
        let helpers = mgmt?.privilegedHelperPaths.count ?? 0
        let surface = mgmt?.managementPlanePresent == true || cli + helpers > 0
        let note = state.collectorNotes["collect.security_mgmt_plane"] != nil
        return surface || note
    }

    private func hasInventory(_ state: CollectedState) -> Bool {
        let mgmt = state.securityMgmtPlane
        let cli = mgmt?.managementCLIPaths.count ?? 0
        let helpers = mgmt?.privilegedHelperPaths.count ?? 0
        let unload = mgmt?.unloadAdjacentHints.count ?? 0
        return cli >= 1 || helpers >= 1 || unload >= 1
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let mgmt = state.securityMgmtPlane
        let cli = mgmt?.managementCLIPaths.count ?? 0
        let helpers = mgmt?.privilegedHelperPaths.count ?? 0
        let unload = mgmt?.unloadAdjacentHints.count ?? 0
        let productsPresent = state.securityProducts.contains(where: \.present)
        let sensorThin =
            state.esf?.clientPaths.isEmpty == true
            || (state.securityProducts.filter(\.present).isEmpty
                && state.collectorNotes["collect.esf_endpoint_security"] != nil)
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let sipOff = state.protections?.sipEnabled == false

        var evidence: [Evidence] = [
            Evidence(
                type: "mgmt_summary",
                detail:
                    "cli=\(cli) helpers=\(helpers) unloadHints=\(unload) "
                    + "productsPresent=\(productsPresent) sensorThin=\(sensorThin) "
                    + "remote=\(remote) sipOff=\(sipOff)"
            ),
        ]
        if let mgmt {
            for path in (mgmt.managementCLIPaths + mgmt.privilegedHelperPaths).prefix(12) {
                evidence.append(Evidence(type: "mgmt_path", path: path, detail: "management-plane path"))
            }
            for n in mgmt.notes.prefix(6) {
                evidence.append(Evidence(type: "mgmt_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never unloads system extensions, never stops EDR agents, "
                    + "never weaponizes security-product management XPC or CLI unload paths."
            )
        )

        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let helpers = state.securityMgmtPlane?.privilegedHelperPaths.count ?? 0
        let productsPresent = state.securityProducts.contains(where: \.present)
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let sipOff = state.protections?.sipEnabled == false
        let severity: Severity
        if remote && (helpers >= 1 || sipOff) {
            severity = .medium
        } else if productsPresent || helpers >= 1 {
            severity = .low
        } else {
            severity = .info
        }

        return Finding(id: Self.id, title: productsPresent
                    ? "Security-product management-plane surface (unload class inventory)"
                    : "Security management-plane tooling surface (sysext/CLI class)", severity: severity, category: .securityProduct, resolution: .init(evidence: evidence, attackTechniques: ["T1562.001", "T1543", "T1218"], remediation: [
                    "Lock down vendor uninstallers and management CLIs via MDM and least privilege",
                    "Monitor systemextensionsctl / launchctl / privileged-helper activity via EDR",
                    "Ensure tamper protection is enabled on enterprise security products",
                    "OPSEC: Rootstock Red documents management-plane class only - never unloads sensors",
                ], falsePositiveNotes: "systemextensionsctl and launchctl are stock tools. Prioritize hosts with "
                    + "security-product helpers and remote access for defense-impairment narrative."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN", "EXEC"]))
    }
}
