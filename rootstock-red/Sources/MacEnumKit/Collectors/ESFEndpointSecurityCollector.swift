import Foundation
import RootstockCore

/// Endpoint Security / EDR sensor posture via path heuristics (assess-safe).
///
/// Research basis: ESF research talks, commercial EDR path catalogs, sysext inventory ideas.
/// Safety and behavior: typed `ESFPostureState` + sensor-gap inputs for vectors; no client unload;
/// **Apple ES infrastructure is never counted as a third-party EDR client** (stock macOS
/// always has EndpointSecurity.framework / endpointsecurityd).
public struct ESFEndpointSecurityCollector: Collector {
    public static let id = "collect.esf_endpoint_security"
    public static let cost: CollectorCost = .medium

    /// Always-present (or near-always) Apple ES infrastructure - not third-party clients.
    private static let appleInfrastructureProbes: [(name: String, path: String)] = [
        ("EndpointSecurity.framework", "/System/Library/Frameworks/EndpointSecurity.framework"),
        ("EndpointSecurity.framework (Library)", "/Library/Frameworks/EndpointSecurity.framework"),
        ("endpointsecurityd", "/usr/libexec/endpointsecurityd"),
    ]

    /// Third-party ES client / EDR support path probes (presence only).
    /// Do not include bare `/Library/SystemExtensions` - that directory exists on stock macOS.
    private static let thirdPartyClientProbes: [(name: String, path: String)] = [
        ("CrowdStrike Falcon", "/Library/CS/falconctl"),
        ("CrowdStrike app", "/Applications/Falcon.app"),
        ("SentinelOne", "/Applications/SentinelOne"),
        ("SentinelOne agent", "/Library/Sentinel"),
        ("CarbonBlack", "/Applications/VMware Carbon Black Cloud"),
        ("CarbonBlack sensor", "/Library/Application Support/com.vmware.carbonblack"),
        ("Microsoft Defender", "/Applications/Microsoft Defender.app"),
        ("Microsoft Defender data", "/Library/Application Support/Microsoft/Defender"),
        ("Jamf Protect", "/Library/Application Support/JamfProtect"),
        ("Jamf Protect app", "/Applications/JamfProtect.app"),
        ("Cortex XDR", "/Library/Application Support/PaloAltoNetworks/Traps"),
        ("Osquery", "/usr/local/bin/osqueryd"),
        ("Osquery app", "/opt/osquery/bin/osqueryd"),
        ("Santa", "/Applications/Santa.app"),
        ("BlockBlock", "/Applications/BlockBlock.app"),
        ("LuLu", "/Applications/LuLu.app"),
    ]

    /// Path substrings that indicate Apple-owned system extensions (not third-party EDR).
    private static let appleSysextMarkers: [String] = [
        "com.apple.",
        "/System/Library/",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "ESF/EDR posture: Apple infrastructure vs third-party clients separated - no client unload",
        ]
        let apple = Self.appleInfrastructure(fileManager: fm, notes: &notes)
        let directClients = Self.directClients(fileManager: fm, notes: &notes)
        let systemExtensions = Self.systemExtensionClients(fileManager: fm, notes: &notes)
        let thirdPartyClients = Self.uniquePathsInDiscoveryOrder(directClients.paths + systemExtensions.paths)
        let edrHints = Array(Set(directClients.hints)).sorted()
        let appleInfra = Self.uniquePaths(apple.paths)

        let frameworkPresent = apple.frameworkPresent
        let thirdPartySysextCount = systemExtensions.paths.count

        var state = CollectedState()
        state.esf = ESFPostureState(
            frameworkPresent: frameworkPresent,
            clientPaths: thirdPartyClients,
            systemExtensionCount: thirdPartySysextCount,
            edrHints: edrHints,
            notes: notes
        )
        // Record apple infra in notes only (also mirror in collector note for gap detection).
        state.collectorNotes[Self.id] =
            "framework=\(frameworkPresent.map(String.init(describing:)) ?? "nil") "
            + "thirdPartyClients=\(thirdPartyClients.count) "
            + "thirdPartySysext≈\(thirdPartySysextCount) "
            + "edrHints=\(edrHints.count) "
            + "appleInfra=\(appleInfra.count)"
        // Explicit gap-friendly token when no third-party clients (stock OS still has appleInfra).
        if thirdPartyClients.isEmpty && edrHints.isEmpty {
            state.collectorNotes["esf.sensor_gap"] =
                "third_party_clients=0 apple_infra_only=\(appleInfra.isEmpty ? "false" : "true")"
        }
        return state
    }

    private static func appleInfrastructure(
        fileManager: FileManager,
        notes: inout [String]
    ) -> (paths: [String], frameworkPresent: Bool?) {
        let paths = appleInfrastructureProbes.compactMap { probe -> String? in
            guard fileManager.fileExists(atPath: probe.path) else { return nil }
            notes.append("apple_infra: \(probe.name) path=\(probe.path)")
            return probe.path
        }
        let frameworkPresent = paths.contains { $0.contains("EndpointSecurity.framework") } ? true : nil
        if frameworkPresent == nil {
            notes.append("EndpointSecurity.framework path not observed (unexpected on modern macOS)")
        }
        return (paths, frameworkPresent)
    }

    private static func directClients(
        fileManager: FileManager,
        notes: inout [String]
    ) -> (paths: [String], hints: [String]) {
        let probes = thirdPartyClientProbes.filter { fileManager.fileExists(atPath: $0.path) }
        for probe in probes {
            notes.append("third_party_client: \(probe.name) path=\(probe.path)")
        }
        return (probes.map(\.path), probes.map(\.name))
    }

    private static func systemExtensionClients(
        fileManager: FileManager,
        notes: inout [String]
    ) -> (paths: [String], count: Int) {
        let root = URL(fileURLWithPath: "/Library/SystemExtensions", isDirectory: true)
        guard fileManager.fileExists(atPath: root.path) else {
            notes.append("systemExtension root absent")
            return ([], 0)
        }
        notes.append("systemExtension root present (directory existence ≠ EDR client)")
        guard let contents = try? fileManager.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            notes.append("systemExtension root present but listing denied")
            return ([], 0)
        }

        let allExtensions = contents.flatMap { systemExtensions(in: $0, fileManager: fileManager) }
        let thirdPartyPaths = allExtensions.filter { !isAppleOwnedSysext($0) }
        for path in allExtensions where isAppleOwnedSysext(path) {
            notes.append("apple_sysext (ignored for client count): \(path)")
        }
        for path in thirdPartyPaths {
            notes.append("third_party_sysext: \(path)")
        }
        notes.append("sysext thirdParty=\(thirdPartyPaths.count) totalListed=\(allExtensions.count)")
        return (thirdPartyPaths, thirdPartyPaths.count)
    }

    private static func systemExtensions(in item: URL, fileManager: FileManager) -> [String] {
        if item.pathExtension == "systemextension" {
            return [item.path]
        }
        let nested = (try? fileManager.contentsOfDirectory(
            at: item,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )) ?? []
        return nested.filter { $0.pathExtension == "systemextension" }.map(\.path)
    }

    private static func uniquePaths(_ paths: [String]) -> [String] {
        Array(Set(paths)).sorted()
    }

    private static func uniquePathsInDiscoveryOrder(_ paths: [String]) -> [String] {
        var seen = Set<String>()
        return paths.filter { seen.insert($0).inserted }
    }

    /// Whether a systemextension path looks Apple-owned (not a third-party EDR client).
    public static func isAppleOwnedSysext(_ path: String) -> Bool {
        let lower = path.lowercased()
        return appleSysextMarkers.contains { lower.contains($0.lowercased()) }
    }

    /// Test helper: classify a probe path as Apple infrastructure (not third-party client).
    public static func isAppleInfrastructurePath(_ path: String) -> Bool {
        appleInfrastructureProbes.contains { $0.path == path }
            || path == "/Library/SystemExtensions"
            || path.hasPrefix("/System/Library/Frameworks/EndpointSecurity")
            || path == "/usr/libexec/endpointsecurityd"
    }
}
