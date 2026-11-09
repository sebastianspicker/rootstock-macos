import Foundation
import RootstockCore

/// Launchd disabled / override depth posture.
///
/// Research basis: disabled.plist / overrides.plist defense-evasion research (Santa/Falcon disable class).
/// Safety and behavior: security-product disable depth ranking; never writes overrides or unloads jobs.
public struct LaunchdOverrideDepthCollector: Collector {
    public static let id = "collect.launchd_override_depth"
    public static let cost: CollectorCost = .low

    private static let overridePaths: [String] = [
        "/var/db/com.apple.xpc.launchd/disabled.plist",
        "/var/db/com.apple.xpc.launchd/disabled.\(AssessedHome.userID).plist",
        "/var/db/launchd.db/com.apple.launchd/overrides.plist",
        "/var/db/launchd.db/com.apple.launchd.peruser.\(AssessedHome.userID)/overrides.plist",
    ]

    private static let securityHints: [String] = [
        "com.google.santa",
        "com.crowdstrike.falcon",
        "com.jamf.management",
        "com.microsoft.wdav",
        "com.apple.security",
        "osquery",
    ]

    private static let keepalivePaths: [String] = [
        "/System/Library/LaunchDaemons",
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        AssessedHome.path + "/Library/LaunchAgents",
    ]

    public init() {}

    /// Labels whose value means "disabled" (`true`; legacy overrides.plist: dict with `Disabled = true`).
    /// Returns nil when the data is oversized, unparseable, or has no disabled entry (not an override).
    static func disabledLabels(in data: Data) -> [String]? {
        guard data.count < 2_000_000,
              let plist = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any]
        else { return nil }
        let labels = plist.compactMap { key, value -> String? in
            if let flag = value as? Bool { return flag ? key : nil }
            if let dict = value as? [String: Any], dict["Disabled"] as? Bool == true { return key }
            return nil
        }.sorted()
        return labels.isEmpty ? nil : labels
    }

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Launchd override depth: path/meta only - never disables jobs or writes overrides.plist",
        ]

        var overrides: [String] = []
        for path in Self.overridePaths where fm.fileExists(atPath: path) {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let disabled = Self.disabledLabels(in: data) else { continue }
            overrides.append(path)
            notes.append("override_path: \(path)")
            for hint in Self.securityHints where disabled.contains(where: { $0.localizedCaseInsensitiveContains(hint) }) {
                notes.append("security_label_hint_in_override: \(hint) @ \(path)")
            }
        }

        var securityDisabled: [String] = []
        for note in notes where note.contains("security_label_hint_in_override:") {
            let hint = note.replacingOccurrences(of: "security_label_hint_in_override: ", with: "")
            securityDisabled.append(hint)
        }

        var keepalive: [String] = []
        for path in Self.keepalivePaths where fm.fileExists(atPath: path) {
            keepalive.append(path)
            notes.append("keepalive_adjacent: \(path)")
        }

        overrides = Array(Set(overrides)).sorted()
        securityDisabled = Array(Set(securityDisabled)).sorted()
        keepalive = Array(Set(keepalive)).sorted()

        let surface = !overrides.isEmpty || !securityDisabled.isEmpty

        var state = CollectedState()
        state.launchdOverrideDepth = LaunchdOverrideDepthState(
            overridePlistPaths: overrides,
            securityDisabledHints: securityDisabled,
            keepaliveAdjacentPaths: keepalive,
            overrideSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "overrides=\(overrides.count) securityHints=\(securityDisabled.count) keepalive=\(keepalive.count) surface=\(surface)"
        return state
    }
}
