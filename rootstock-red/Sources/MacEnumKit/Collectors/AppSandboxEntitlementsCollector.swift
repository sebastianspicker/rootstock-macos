import Foundation
import RootstockCore

/// App sandbox / entitlement thick-client surface (Wave-7).
///
/// Research basis: MacPEAS / inject-check entitlement inventories; thick-client risk lists.
/// Safety and behavior: typed `AppSandboxEntitlementState`; reuses inject/codesign signals; never
/// mutates entitlements or strips sandbox.
public struct AppSandboxEntitlementsCollector: Collector {
    public static let id = "collect.app_sandbox_entitlements"
    public static let cost: CollectorCost = .low

    /// High-value thick-client samples under /Applications (path presence only).
    private static let thickClientCandidates: [String] = [
        "/Applications/Google Chrome.app",
        "/Applications/Firefox.app",
        "/Applications/Microsoft Edge.app",
        "/Applications/Slack.app",
        "/Applications/Zoom.app",
        "/Applications/Microsoft Teams.app",
        "/Applications/Discord.app",
        "/Applications/Visual Studio Code.app",
        "/Applications/Cursor.app",
        "/Applications/Spotify.app",
        "/Applications/1Password.app",
        "/Applications/Docker.app",
        "/Applications/Notion.app",
        "/Applications/Figma.app",
        "/Applications/Postman.app",
        "/Applications/iTerm.app",
        "/Applications/Warp.app",
        "/Applications/Obsidian.app",
        "/Applications/Telegram.app",
        "/Applications/WhatsApp.app",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "App sandbox/entitlement surface: path + risk-class inventory - no entitlement mutation",
        ]
        let appSamples = Self.sampleApps(fileManager: fm, notes: &notes)
        let supportPaths = Self.supportPaths(fileManager: fm, notes: &notes)
        let unsandboxedRiskPaths = Self.unsandboxedRiskPaths(for: appSamples, notes: &notes)

        var state = CollectedState()
        state.appSandboxEntitlements = AppSandboxEntitlementState(
            appSamples: appSamples,
            sandboxedHints: supportPaths.sandboxed,
            dangerousEntitlementHints: supportPaths.dangerous,
            unsandboxedRiskPaths: unsandboxedRiskPaths,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "apps=\(appSamples.count) sandboxedHints=\(supportPaths.sandboxed.count) "
            + "dangerous=\(supportPaths.dangerous.count) riskPaths=\(unsandboxedRiskPaths.count)"
        return state
    }

    private static func sampleApps(fileManager: FileManager, notes: inout [String]) -> [String] {
        var paths = thickClientCandidates.filter(fileManager.fileExists(atPath:))
        for path in paths {
            notes.append("thick_client_present: \(path)")
        }

        let userApps = NSHomeDirectory() + "/Applications"
        if let names = try? fileManager.contentsOfDirectory(atPath: userApps) {
            for name in names.prefix(12) where name.hasSuffix(".app") {
                let path = (userApps as NSString).appendingPathComponent(name)
                paths.append(path)
                notes.append("user_app_sample: \(path)")
            }
        }
        return Array(Set(paths)).sorted()
    }

    private static func supportPaths(
        fileManager: FileManager,
        notes: inout [String]
    ) -> (sandboxed: [String], dangerous: [String]) {
        let sandboxSupport = [
            "/System/Library/Sandbox",
            "/usr/lib/libsandbox.1.dylib",
            "/System/Library/Frameworks/Security.framework",
        ].filter(fileManager.fileExists(atPath:))
        for path in sandboxSupport {
            notes.append("sandbox_support: \(path)")
        }

        let dangerousSupport = ["/usr/bin/codesign", "/usr/bin/security", "/usr/bin/csreq"]
            .filter(fileManager.fileExists(atPath:))
            .map { "tool:\($0)" }
        let containersRoot = NSHomeDirectory() + "/Library/Containers"
        let sandboxed = sandboxSupport + [containersRoot].filter(fileManager.fileExists(atPath:))
        notes.append(
            fileManager.fileExists(atPath: containersRoot)
                ? "containers_root_present: \(containersRoot)"
                : "containers_root_absent (many unsandboxed apps expected)"
        )
        return (Array(Set(sandboxed)).sorted(), Array(Set(dangerousSupport)).sorted())
    }

    private static func unsandboxedRiskPaths(for appSamples: [String], notes: inout [String]) -> [String] {
        let keywords = ["slack", "code", "discord", "cursor", "postman", "obsidian"]
        let paths = appSamples.filter { path in keywords.contains { path.localizedCaseInsensitiveContains($0) } }
        for path in paths {
            notes.append("thick_client_risk_class: \(path)")
        }
        return Array(Set(paths)).sorted()
    }
}
