import Foundation
import RootstockCore

/// NetworkExtension / VPN / content-filter posture via path heuristics (assess-safe).
///
/// Research basis: NE research (Packet Tunnel / Content Filter / App Proxy), vendor firewall
/// catalogs (LuLu, Little Snitch), networkextension prefs inventory.
/// Safety and behavior: typed `NetworkExtensionState` for VPN/filter gap analysis; path probes only,
/// no VPN config dump, no NE session control, no unload of system extensions.
///
/// Honesty: stock macOS always has `pf` config paths and often Application Firewall prefs.
/// Those are recorded as **stock OS artifacts** in notes only - they must never fill
/// `contentFilterHints` (enterprise / third-party filter signals), or gap vectors never fire.
public struct NetworkExtensionCollector: Collector {
    public static let id = "collect.network_extension"
    public static let cost: CollectorCost = .low

    private static let frameworkProbes: [String] = [
        "/System/Library/Frameworks/NetworkExtension.framework",
        "/Library/Frameworks/NetworkExtension.framework",
    ]

    /// VPN / NE preference plists (presence only - never read secrets).
    private static let vpnConfigProbes: [String] = [
        "/Library/Preferences/com.apple.networkextension.plist",
        "/Library/Preferences/com.apple.networkextension.necp.plist",
        "/Library/Preferences/com.apple.networkextension.uuidcache.plist",
        "/Library/Preferences/com.apple.networkextension.control.plist",
        "/Library/Preferences/SystemConfiguration/com.apple.networkextension.plist",
    ]

    /// Enterprise / NE content-filter signals only (NOT stock pf / ALF).
    private static let enterpriseContentFilterProbes: [(name: String, path: String)] = [
        ("content_filter_prefs", "/Library/Preferences/com.apple.networkextension.filter.plist"),
        ("webcontent_filter", "/Library/Preferences/com.apple.webcontentfilter.plist"),
        ("managed_webcontent", "/Library/Managed Preferences/com.apple.webcontent-filter.plist"),
    ]

    /// Always-or-nearly-always present on stock macOS - notes only, never contentFilterHints.
    private static let stockNetworkArtifacts: [(name: String, path: String)] = [
        ("pf_conf", "/etc/pf.conf"),
        ("pf_anchors", "/etc/pf.anchors"),
        ("application_firewall_alf", "/Library/Preferences/com.apple.alf.plist"),
    ]

    private static let packetTunnelProbes: [(name: String, path: String)] = [
        ("packet_tunnel_prefs", "/Library/Preferences/com.apple.networkextension.tunnel.plist"),
        ("vpn_neconfiguration", "/Library/Preferences/com.apple.networkextension.uuidcache.plist"),
    ]

    /// Third-party NE / host firewall style apps (presence only).
    private static let neAppProbes: [(name: String, path: String)] = [
        ("LuLu", "/Applications/LuLu.app"),
        ("Little Snitch", "/Applications/Little Snitch.app"),
        ("Little Snitch Configuration", "/Applications/Little Snitch Configuration.app"),
        ("Radio Silence", "/Applications/Radio Silence.app"),
        ("Hands Off!", "/Applications/Hands Off!.app"),
        ("TripMode", "/Applications/TripMode.app"),
        ("Murus", "/Applications/Murus.app"),
        ("Vallum", "/Applications/Vallum.app"),
        ("Cloudflare WARP", "/Applications/Cloudflare WARP.app"),
        ("Tailscale", "/Applications/Tailscale.app"),
        ("WireGuard", "/Applications/WireGuard.app"),
        ("Viscosity", "/Applications/Viscosity.app"),
        ("Tunnelblick", "/Applications/Tunnelblick.app"),
        ("ProtonVPN", "/Applications/ProtonVPN.app"),
        ("NordVPN", "/Applications/NordVPN.app"),
    ]

    public init() {}

    /// Whether a path is a stock OS network artifact (pf / ALF) - never an enterprise filter hit.
    public static func isStockNetworkArtifactPath(_ path: String) -> Bool {
        stockNetworkArtifacts.contains { $0.path == path }
            || path == "/etc/pf.conf"
            || path == "/etc/pf.anchors"
            || path.hasSuffix("/com.apple.alf.plist")
    }

    /// Classify a content-filter probe name as enterprise (true) vs stock noise (false).
    public static func isEnterpriseContentFilterHint(_ hint: String) -> Bool {
        let lower = hint.lowercased()
        if lower.contains("pf_conf") || lower.contains("pf_anchors") || lower.contains("application_firewall") {
            return false
        }
        if lower.contains("/etc/pf.conf") || lower.contains("/etc/pf.anchors") {
            return false
        }
        if lower.contains("com.apple.alf.plist") {
            return false
        }
        return true
    }

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "NetworkExtension posture: path heuristics only - no config/secret dump, no NE control",
            "Stock pf/ALF paths recorded as stock_os artifacts only (not contentFilterHints)",
        ]

        let frameworkPresent = Self.frameworkPresence(fileManager: fm, notes: &notes)

        // Note-only: bare SystemExtensions root is stock-macOS noise (see ESF collector).
        let sysextRoot = "/Library/SystemExtensions"
        if fm.fileExists(atPath: sysextRoot) {
            notes.append(
                "systemExtension root present at \(sysextRoot) (directory existence ≠ NE client)"
            )
        }

        let vpnConfigPaths = Self.vpnConfigPaths(fileManager: fm, notes: &notes)
        let stockArtifactCount = Self.recordStockArtifacts(fileManager: fm, notes: &notes)
        let contentFilterHints = Self.probeHints(
            Self.enterpriseContentFilterProbes,
            prefix: "enterprise_content_filter",
            fileManager: fm,
            notes: &notes
        )
        // Defensive: never let stock paths leak into contentFilterHints.
        let filteredContentFilterHints = Array(Set(contentFilterHints))
            .filter { Self.isEnterpriseContentFilterHint($0) }
            .sorted()
        let packetTunnelHints = Self.probeHints(
            Self.packetTunnelProbes,
            prefix: "packet_tunnel",
            fileManager: fm,
            notes: &notes
        )
        let neAppPaths = Self.appPaths(fileManager: fm, notes: &notes)

        var state = CollectedState()
        state.networkExtension = NetworkExtensionState(
            frameworkPresent: frameworkPresent,
            vpnConfigPaths: vpnConfigPaths,
            contentFilterHints: filteredContentFilterHints,
            packetTunnelHints: packetTunnelHints,
            neAppPaths: neAppPaths,
            notes: notes
        )
        let frameworkNote = frameworkPresent.map(String.init(describing:)) ?? "nil"
        state.collectorNotes[Self.id] = "framework=\(frameworkNote) vpnConfigs=\(vpnConfigPaths.count) "
            + "contentFilter=\(filteredContentFilterHints.count) packetTunnel=\(packetTunnelHints.count) "
            + "neApps=\(neAppPaths.count) stockNetworkArtifacts=\(stockArtifactCount)"
        // Explicit gap-friendly token when no enterprise filter inventory (stock pf alone is not coverage).
        if filteredContentFilterHints.isEmpty && neAppPaths.isEmpty {
            state.collectorNotes["ne.filter_gap"] =
                "enterprise_content_filter=0 neApps=0 stock_os_network=\(stockArtifactCount)"
        }
        return state
    }

    private static func frameworkPresence(fileManager: FileManager, notes: inout [String]) -> Bool? {
        let paths = frameworkProbes.filter { fileManager.fileExists(atPath: $0) }
        for path in paths {
            notes.append("framework present: \(path)")
        }
        guard !paths.isEmpty else {
            notes.append("NetworkExtension.framework not observed at catalog paths")
            return false
        }
        return true
    }

    private static func vpnConfigPaths(fileManager: FileManager, notes: inout [String]) -> [String] {
        var paths = vpnConfigProbes.filter { fileManager.fileExists(atPath: $0) }
        for path in paths {
            notes.append("vpn_config path: \(path)")
        }
        let preferencesDirectory = "/Library/Preferences"
        if let entries = try? fileManager.contentsOfDirectory(atPath: preferencesDirectory) {
            for name in entries where name.hasPrefix("com.apple.networkextension") {
                let path = (preferencesDirectory as NSString).appendingPathComponent(name)
                guard !paths.contains(path), fileManager.fileExists(atPath: path) else { continue }
                paths.append(path)
                notes.append("vpn_config listed: \(path)")
            }
        }
        return Array(Set(paths)).sorted()
    }

    private static func recordStockArtifacts(fileManager: FileManager, notes: inout [String]) -> Int {
        let probes = stockNetworkArtifacts.filter { fileManager.fileExists(atPath: $0.path) }
        for probe in probes {
            notes.append("stock_os_network: \(probe.name) path=\(probe.path)")
        }
        return probes.count
    }

    private static func probeHints(
        _ probes: [(name: String, path: String)],
        prefix: String,
        fileManager: FileManager,
        notes: inout [String]
    ) -> [String] {
        let present = probes.filter { fileManager.fileExists(atPath: $0.path) }
        for probe in present {
            notes.append("\(prefix): \(probe.name) path=\(probe.path)")
        }
        return Array(Set(present.map { "\($0.name):\($0.path)" })).sorted()
    }

    private static func appPaths(fileManager: FileManager, notes: inout [String]) -> [String] {
        let probes = neAppProbes.filter { fileManager.fileExists(atPath: $0.path) }
        for probe in probes {
            notes.append("ne_app: \(probe.name) path=\(probe.path)")
        }
        return Array(Set(probes.map(\.path))).sorted()
    }
}
