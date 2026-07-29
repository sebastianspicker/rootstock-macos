import Foundation
import RootstockCore

/// Security-product management-plane / privileged-XPC unload class (Wave-8).
///
/// Research basis: XM Cyber–class security-tool management-plane research; sysext unload awareness.
/// Safety and behavior: typed `SecurityMgmtPlaneState`; path inventory only - never unloads sensors.
public struct SecurityMgmtPlaneCollector: Collector {
    public static let id = "collect.security_mgmt_plane"
    public static let cost: CollectorCost = .low

    private static let managementCLIPaths: [String] = [
        "/usr/bin/systemextensionsctl",
        "/usr/bin/kmutil",
        "/usr/sbin/kextunload",
        "/bin/launchctl",
        "/usr/bin/xpcutil",
        "/usr/sbin/system_profiler",
        "/Applications/Falcon.app",
        "/Library/CS/falconctl",
        "/usr/local/bin/falconctl",
        "/Applications/CrowdStrike/Falcon.app",
        "/Library/Application Support/CrowdStrike",
        "/Applications/SentinelOne",
        "/Library/Sentinel/sentinel-agent.bundle",
        "/usr/local/bin/sentinelctl",
        "/Applications/Microsoft Defender.app",
        "/Library/Application Support/Microsoft/Defender",
        "/Applications/Carbon Black Cloud.app",
        "/Applications/Jamf.app",
        "/usr/local/bin/jamf",
        "/Library/Application Support/JAMF",
    ]

    private static let privilegedHelperRoots: [String] = [
        "/Library/PrivilegedHelperTools",
        "/Library/SystemExtensions",
        "/Library/Extensions",
    ]

    /// Name tokens that suggest security-product management adjacency (path-only).
    private static let securityNameTokens: [String] = [
        "falcon", "crowdstrike", "sentinel", "defender", "carbon", "jamf",
        "eset", "malwarebytes", "sophos", "trend", "symantec", "norton",
        "bitdefender", "kaspersky", "lulu", "blockblock", "oversight",
        "endpoint", "edr", "xprotect", "mrt",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Security mgmt-plane surface: management CLI/helper path presence - never unloads sensors",
        ]

        var mgmt: [String] = []
        for path in Self.managementCLIPaths where fm.fileExists(atPath: path) {
            mgmt.append(path)
            notes.append("mgmt_cli_or_product: \(path)")
        }

        var helpers: [String] = []
        var unloadHints: [String] = []
        for root in Self.privilegedHelperRoots {
            guard fm.fileExists(atPath: root) else { continue }
            unloadHints.append(root)
            notes.append("mgmt_root: \(root)")
            if let entries = try? fm.contentsOfDirectory(atPath: root) {
                for entry in entries.prefix(80) where Self.isSecurityHelperName(entry) {
                    let full = (root as NSString).appendingPathComponent(entry)
                    helpers.append(full)
                    notes.append("security_helper_hint: \(full)")
                }
            }
        }

        // Always note systemextensionsctl class if present
        if mgmt.contains(where: { $0.contains("systemextensionsctl") }) {
            unloadHints.append("systemextensionsctl_present")
            notes.append("unload_class: systemextensionsctl path present (inventory only)")
        }

        mgmt = Array(Set(mgmt)).sorted()
        helpers = Array(Set(helpers)).sorted()
        unloadHints = Array(Set(unloadHints)).sorted()

        let surface = !mgmt.isEmpty || !helpers.isEmpty

        var state = CollectedState()
        state.securityMgmtPlane = SecurityMgmtPlaneState(
            managementCLIPaths: mgmt,
            privilegedHelperPaths: helpers,
            unloadAdjacentHints: unloadHints,
            managementPlanePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "mgmt=\(mgmt.count) helpers=\(helpers.count) "
            + "unloadHints=\(unloadHints.count) surface=\(surface)"
        return state
    }

    private static func isSecurityHelperName(_ entry: String) -> Bool {
        let lower = entry.lowercased()
        return securityNameTokens.contains { lower.contains($0) }
    }
}
