import Foundation
import RootstockCore

/// PackageKit installer design-based persistence posture (Wave-9).
///
/// Research basis: PackageKit design-based research (installd / package_script_service /
/// InstallerSandboxes class); pkg receipt inventory ideas from MacPEAS-class tools.
/// Safety and behavior: typed `PackageKitInstallerDesignState`; never builds pkgs or invokes installd.
public struct PackageKitInstallerDesignCollector: Collector {
    public static let id = "collect.packagekit_installer_design"
    public static let cost: CollectorCost = .low

    private static let servicePaths: [String] = [
        "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc",
        "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc/Contents/MacOS/package_script_service",
        "/usr/libexec/installd",
        "/System/Library/PrivateFrameworks/PackageKit.framework/Resources/installd",
        "/usr/libexec/system_installd",
        "/System/Library/LaunchDaemons/com.apple.installd.plist",
        "/System/Library/LaunchDaemons/com.apple.system_installd.plist",
    ]

    private static let receiptHistoryPaths: [String] = [
        "/Library/Receipts",
        "/private/var/db/receipts",
        "/var/db/receipts",
        "/Library/Receipts/InstallHistory.plist",
        "/Library/InstallerSandboxes",
        "/private/var/folders",
        "/System/Library/PrivateFrameworks/PackageKit.framework",
    ]

    private static let pluginPaths: [String] = [
        "/Library/Installer Plugins",
        "/System/Library/InstallerPlugins",
        "/Library/InstallerPlugins",
    ]

    private static let toolingPaths: [String] = [
        "/usr/sbin/installer",
        "/usr/sbin/pkgutil",
        "/usr/bin/pkgbuild",
        "/usr/bin/productbuild",
        "/System/Library/CoreServices/Installer.app",
        "/System/Library/PrivateFrameworks/PackageKit.framework",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        var notes = ["PackageKit installer design surface: path presence only - never builds pkgs, never invokes installd/package_script_service"]
        let services = existing(Self.servicePaths, notePrefix: "installer_service", notes: &notes)
        let receipts = receiptPaths(notes: &notes)
        let plugins = existing(Self.pluginPaths, notePrefix: "installer_plugin_dir", notes: &notes)
        let tooling = existing(Self.toolingPaths, notePrefix: "installer_tool", notes: &notes)
        return Self.state(services: services, receipts: receipts, plugins: plugins, tooling: tooling, notes: notes)
    }


    private func existing(_ paths: [String], notePrefix: String, notes: inout [String]) -> [String] {
        let matches = paths.filter { FileManager.default.fileExists(atPath: $0) }
        notes.append(contentsOf: matches.map { "\(notePrefix): \($0)" })
        return Array(Set(matches)).sorted()
    }

    private func receiptPaths(notes: inout [String]) -> [String] {
        let matches = Self.receiptHistoryPaths.filter { FileManager.default.fileExists(atPath: $0) }
        let receipts = matches.filter { $0 != "/private/var/folders" }
        notes.append(contentsOf: receipts.map { "receipt_or_history: \($0)" })
        if matches.contains("/private/var/folders") {
            notes.append("var_folders_present: /private/var/folders (InstallerSandboxes class may live under randomized subpaths - not enumerated)")
        }
        return Array(Set(receipts)).sorted()
    }

    private static func state(services: [String], receipts: [String], plugins: [String], tooling: [String], notes: [String]) -> CollectedState {
        let surface = !services.isEmpty || receipts.count >= 1 || tooling.count >= 2
        var state = CollectedState()
        state.packageKitInstallerDesign = PackageKitInstallerDesignState(installerServicePaths: services, receiptAndHistoryPaths: receipts, installerPluginPaths: plugins, toolingPaths: tooling, designSurfacePresent: surface, notes: notes)
        state.collectorNotes[Self.id] = "services=\(services.count) receipts=\(receipts.count) " + "plugins=\(plugins.count) tooling=\(tooling.count) surface=\(surface)"
        return state
    }
}
