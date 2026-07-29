import Foundation
import RootstockCore

/// Path-to-impact: virtualization / container dual-use surface.
///
/// Research basis: Docker/UTM dual-use research; PEASS virt inventories.
/// Safety and behavior: typed compound with remote/dev toolchain; never starts VMs or harvests secrets.
public struct VirtContainerDualUseVector: Check {
    public static let id = "rootstock.vector.virt.container_dual_use"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard hasSurface(state), hasImpact(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func hasSurface(_ state: CollectedState) -> Bool {
        let virt = state.virtualizationContainers
        let containers = virt?.containerToolPaths.count ?? 0
        let hypervisors = virt?.hypervisorAppPaths.count ?? 0
        let dual = virt?.dualUsePresent == true
        let note = state.collectorNotes["collect.virtualization_containers"] != nil
        return dual || containers > 0 || hypervisors > 0 || note
    }

    private func hasImpact(_ state: CollectedState) -> Bool {
        let virt = state.virtualizationContainers
        let containers = virt?.containerToolPaths.count ?? 0
        let hypervisors = virt?.hypervisorAppPaths.count ?? 0
        let frameworks = virt?.frameworkPaths.count ?? 0
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let dev =
            state.developerToolchain?.xcodePresent == true
            || state.developerToolchain?.commandLineToolsPresent == true
            || !(state.developerToolchain?.dualUseBinaries.isEmpty ?? true)
        let weakProt = state.protections?.sipEnabled == false
        return remote || dev || weakProt || containers + hypervisors >= 1 || frameworks > 0
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let virt = state.virtualizationContainers
        let containers = virt?.containerToolPaths.count ?? 0
        let hypervisors = virt?.hypervisorAppPaths.count ?? 0
        let frameworks = virt?.frameworkPaths.count ?? 0
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let dev = state.developerToolchain?.xcodePresent == true
            || state.developerToolchain?.commandLineToolsPresent == true
            || !(state.developerToolchain?.dualUseBinaries.isEmpty ?? true)
        let weakProt = state.protections?.sipEnabled == false

        var evidence: [Evidence] = [
            Evidence(
                type: "virt_summary",
                detail:
                    "containers=\(containers) hypervisors=\(hypervisors) frameworks=\(frameworks) "
                    + "remote=\(remote) devToolchain=\(dev) sipOff=\(weakProt)"
            ),
        ]
        if let virt {
            for path in (virt.containerToolPaths + virt.hypervisorAppPaths + virt.frameworkPaths).prefix(15) {
                evidence.append(Evidence(type: "virt_path", path: path, detail: "dual-use virt/container path"))
            }
            for n in virt.notes.prefix(6) {
                evidence.append(Evidence(type: "virt_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never starts containers/VMs, never harvests image secrets, never ships VM-escape packs."
            )
        )

        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let containers = state.virtualizationContainers?.containerToolPaths.count ?? 0
        let hypervisors = state.virtualizationContainers?.hypervisorAppPaths.count ?? 0
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let severity: Severity = (remote && (containers > 0 || hypervisors > 0)) ? .medium : .low

        return Finding(id: Self.id, title: remote
                    ? "Virtualization/container dual-use surface with remote access compound"
                    : "Virtualization / container dual-use surface", severity: severity, category: .lool, resolution: .init(evidence: evidence, attackTechniques: ["T1564", "T1202", "T1610", "T1059"], remediation: [
                    "Limit Docker/VM tooling on high-value production endpoints when not required",
                    "Monitor nested execution and virt helper daemons under EDR",
                    "Separate engineer virt workstations from tier-0 admin access",
                    "OPSEC: Rootstock Red does not deploy container C2 or hypervisor escapes",
                ], falsePositiveNotes: "Developer workstations commonly install Docker/UTM. Prioritize remote-access compounds."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 20, esfExpected: ["OPEN", "EXEC"]))
    }
}
