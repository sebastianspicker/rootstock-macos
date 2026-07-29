import Foundation
import RootstockCore

/// Virtualization / container dual-use surface (Wave-7).
///
/// Research basis: PEASS virt inventories; dual-use Docker/UTM research themes.
/// Safety and behavior: typed `VirtualizationContainerState`; never starts VMs/containers or harvests image secrets.
public struct VirtualizationContainersCollector: Collector {
    public static let id = "collect.virtualization_containers"
    public static let cost: CollectorCost = .low

    private static let containerToolPaths: [String] = [
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        "/usr/local/bin/docker-compose",
        "/opt/homebrew/bin/docker-compose",
        "/usr/local/bin/colima",
        "/opt/homebrew/bin/colima",
        "/usr/local/bin/lima",
        "/opt/homebrew/bin/lima",
        "/usr/local/bin/limactl",
        "/opt/homebrew/bin/limactl",
        "/usr/local/bin/podman",
        "/opt/homebrew/bin/podman",
        "/usr/local/bin/nerdctl",
        "/opt/homebrew/bin/nerdctl",
        "/Applications/Docker.app",
        "/Applications/OrbStack.app",
        "/Applications/Rancher Desktop.app",
    ]

    private static let hypervisorAppPaths: [String] = [
        "/Applications/UTM.app",
        "/Applications/Parallels Desktop.app",
        "/Applications/VMware Fusion.app",
        "/Applications/VirtualBox.app",
        "/Applications/Multipass.app",
        "/usr/local/bin/multipass",
        "/opt/homebrew/bin/multipass",
        "/Applications/Windows App.app",
        "/Applications/Microsoft Remote Desktop.app",
    ]

    private static let frameworkPaths: [String] = [
        "/System/Library/Frameworks/Virtualization.framework",
        "/Library/Apple/System/Library/PrivateFrameworks/Virtualization.framework",
        "/Library/PrivilegedHelperTools/com.docker.vmnetd",
        "/Library/LaunchDaemons/com.docker.vmnetd.plist",
        "/Library/LaunchDaemons/com.docker.socket.plist",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Virtualization/container dual-use: path presence only - no start/stop, no image secret harvest",
        ]

        var containers: [String] = []
        for path in Self.containerToolPaths where fm.fileExists(atPath: path) {
                containers.append(path)
                notes.append("container_tool: \(path)")
        }

        var hypervisors: [String] = []
        for path in Self.hypervisorAppPaths where fm.fileExists(atPath: path) {
                hypervisors.append(path)
                notes.append("hypervisor: \(path)")
        }

        var frameworks: [String] = []
        for path in Self.frameworkPaths where fm.fileExists(atPath: path) {
                frameworks.append(path)
                notes.append("virt_framework_or_helper: \(path)")
        }

        // User config dirs (presence only).
        let home = NSHomeDirectory()
        let userHints = [
            "\(home)/.docker",
            "\(home)/.colima",
            "\(home)/.lima",
            "\(home)/.orbstack",
            "\(home)/Library/Containers/com.docker.docker",
        ]
        for path in userHints where fm.fileExists(atPath: path) {
                containers.append(path)
                notes.append("user_virt_config: \(path)")
        }

        containers = Array(Set(containers)).sorted()
        hypervisors = Array(Set(hypervisors)).sorted()
        frameworks = Array(Set(frameworks)).sorted()

        let dualUse = !containers.isEmpty || !hypervisors.isEmpty

        var state = CollectedState()
        state.virtualizationContainers = VirtualizationContainerState(
            containerToolPaths: containers,
            hypervisorAppPaths: hypervisors,
            frameworkPaths: frameworks,
            dualUsePresent: dualUse,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "containers=\(containers.count) hypervisors=\(hypervisors.count) "
            + "frameworks=\(frameworks.count) dualUse=\(dualUse)"
        return state
    }
}
