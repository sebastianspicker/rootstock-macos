import Foundation
import RootstockCore

/// Path-to-impact: PackageKit installer design-based persistence surface.
///
/// Research basis: PackageKit design-based research (package_script_service / InstallerSandboxes class).
/// Safety and behavior: typed compound with remote/root; never builds pkgs or invokes installd.
public struct PackageKitInstallerDesignVector: Check {
    public static let id = "rootstock.vector.persist.packagekit_installer_design"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard hasSurface(state), hasInventory(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func hasSurface(_ state: CollectedState) -> Bool {
        let pk = state.packageKitInstallerDesign
        let services = pk?.installerServicePaths.count ?? 0
        let receipts = pk?.receiptAndHistoryPaths.count ?? 0
        let tooling = pk?.toolingPaths.count ?? 0
        let surface = pk?.designSurfacePresent == true || services > 0 || receipts > 0 || tooling >= 2
        let note = state.collectorNotes["collect.packagekit_installer_design"] != nil
        return surface || note
    }

    private func hasInventory(_ state: CollectedState) -> Bool {
        let pk = state.packageKitInstallerDesign
        let hasService = (pk?.installerServicePaths.count ?? 0) >= 1
        let hasReceipt = (pk?.receiptAndHistoryPaths.count ?? 0) >= 1
        let hasTooling = (pk?.toolingPaths.count ?? 0) >= 2
        return hasService || hasReceipt || hasTooling
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let pk = state.packageKitInstallerDesign
        let services = pk?.installerServicePaths.count ?? 0
        let receipts = pk?.receiptAndHistoryPaths.count ?? 0
        let tooling = pk?.toolingPaths.count ?? 0
        let plugins = pk?.installerPluginPaths.count ?? 0
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let isRoot = state.host?.isRoot == true
        let sipOff = state.protections?.sipEnabled == false

        var evidence: [Evidence] = [
            Evidence(
                type: "installer_design_summary",
                detail:
                    "services=\(services) receipts=\(receipts) plugins=\(plugins) tooling=\(tooling) "
                    + "remote=\(remote) root=\(isRoot) sipOff=\(sipOff)"
            ),
        ]
        if let pk {
            for path in (pk.installerServicePaths + pk.receiptAndHistoryPaths + pk.toolingPaths).prefix(12) {
                evidence.append(Evidence(type: "installer_path", path: path, detail: "installer design component"))
            }
            for n in pk.notes.prefix(6) {
                evidence.append(Evidence(type: "installer_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never builds malicious packages, never invokes installd/package_script_service, "
                    + "never weaponizes InstallerSandboxes or preinstall/postinstall scripts."
            )
        )

        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let services = state.packageKitInstallerDesign?.installerServicePaths.count ?? 0
        let receipts = state.packageKitInstallerDesign?.receiptAndHistoryPaths.count ?? 0
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let isRoot = state.host?.isRoot == true
        let sipOff = state.protections?.sipEnabled == false
        let severity: Severity
        if remote && services >= 1 && (sipOff || isRoot) {
            severity = .high
        } else if services >= 1 || (receipts >= 2 && remote) {
            severity = .medium
        } else {
            severity = .low
        }

        return Finding(id: Self.id, title: remote
                    ? "PackageKit installer design surface on remotely reachable host"
                    : "PackageKit installer design-based persistence posture", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1546", "T1059", "T1072"], remediation: [
                    "Monitor package_script_service / installd executions and unexpected receipt changes",
                    "Restrict installer rights via MDM where policy allows; review Installer Plugins directories",
                    "Prefer notarized, MDM-distributed software over ad-hoc local pkg installs",
                    "OPSEC: Rootstock Red does not build pkgs or weaponize PackageKit design classes",
                ], falsePositiveNotes: "PackageKit and installd ship with macOS. Prioritize hosts with remote access, "
                    + "unexpected receipts, or SIP-off narratives for engagement ranking."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 20, esfExpected: ["OPEN", "EXEC", "WRITE"]))
    }
}
