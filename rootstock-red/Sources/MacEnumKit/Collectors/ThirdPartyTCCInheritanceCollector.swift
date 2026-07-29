import Foundation
import RootstockCore

/// Third-party TCC-inheritance / embedded-interpreter class (Wave-8).
///
/// Research basis: Electron/TCC inheritance discussions; thick-client interpreter dual-use.
/// Safety and behavior: typed `ThirdPartyTCCInheritanceState`; never forges TCC grants or strips entitlements.
public struct ThirdPartyTCCInheritanceCollector: Collector {
    public static let id = "collect.third_party_tcc_inheritance"
    public static let cost: CollectorCost = .low

    /// High-value apps commonly granted broad TCC domains (path samples).
    private static let thickClientCandidates: [String] = [
        "/Applications/Slack.app",
        "/Applications/Microsoft Teams.app",
        "/Applications/zoom.us.app",
        "/Applications/Discord.app",
        "/Applications/Visual Studio Code.app",
        "/Applications/Cursor.app",
        "/Applications/Google Chrome.app",
        "/Applications/Firefox.app",
        "/Applications/Microsoft Edge.app",
        "/Applications/Figma.app",
        "/Applications/Notion.app",
        "/Applications/Spotify.app",
        "/Applications/1Password.app",
        "/Applications/Docker.app",
        "/Applications/iTerm.app",
        "/Applications/Warp.app",
    ]

    private static let interpreterRelPaths: [String] = [
        "Contents/Frameworks/Electron Framework.framework",
        "Contents/MacOS/Electron",
        "Contents/Resources/app.asar",
        "Contents/Resources/node",
        "Contents/Frameworks/Squirrel.framework",
        "Contents/Helpers",
        "Contents/Resources/python",
        "Contents/Resources/python3",
        "Contents/MacOS/Python",
        "Contents/Frameworks/Chromium Embedded Framework.framework",
        "Contents/Frameworks/ReactiveObjC.framework",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "TCC inheritance surface: thick-client + embedded interpreter path presence - never forges grants",
        ]

        var thick: [String] = []
        var interpreters: [String] = []
        var electron: [String] = []

        for app in Self.thickClientCandidates where fm.fileExists(atPath: app) {
            thick.append(app)
            notes.append("thick_client: \(app)")
            Self.appendEmbeddedComponents(
                for: app,
                fileManager: fm,
                interpreters: &interpreters,
                electron: &electron,
                notes: &notes
            )
        }

        // System-wide interpreters that apps may spawn (path presence only)
        Self.appendHostInterpreters(fileManager: fm, interpreters: &interpreters, notes: &notes)

        thick = Array(Set(thick)).sorted()
        interpreters = Array(Set(interpreters)).sorted()
        electron = Array(Set(electron)).sorted()

        let surface = Self.hasInheritanceSurface(
            thickClients: thick,
            interpreters: interpreters,
            electronHelpers: electron
        )

        var state = CollectedState()
        state.thirdPartyTCCInheritance = ThirdPartyTCCInheritanceState(
            thickClientAppPaths: thick,
            embeddedInterpreterPaths: interpreters,
            electronHelperPaths: electron,
            inheritanceSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "thick=\(thick.count) interpreters=\(interpreters.count) "
            + "electron=\(electron.count) surface=\(surface)"
        return state
    }

    private static func appendEmbeddedComponents(
        for app: String,
        fileManager: FileManager,
        interpreters: inout [String],
        electron: inout [String],
        notes: inout [String]
    ) {
        for relativePath in interpreterRelPaths {
            let fullPath = (app as NSString).appendingPathComponent(relativePath)
            guard fileManager.fileExists(atPath: fullPath) else { continue }

            interpreters.append(fullPath)
            if isElectronComponent(relativePath) {
                electron.append(fullPath)
            }
            notes.append("embedded_component: \(fullPath)")
        }
    }

    private static func appendHostInterpreters(
        fileManager: FileManager,
        interpreters: inout [String],
        notes: inout [String]
    ) {
        let paths = ["/usr/bin/python3", "/usr/bin/ruby", "/usr/local/bin/node", "/opt/homebrew/bin/node"]
        for path in paths where fileManager.fileExists(atPath: path) {
            interpreters.append(path)
            notes.append("host_interpreter: \(path)")
        }
    }

    private static func isElectronComponent(_ relativePath: String) -> Bool {
        let lowercasedPath = relativePath.lowercased()
        return ["electron", "chromium", "node", "asar", "squirrel"].contains {
            lowercasedPath.contains($0)
        }
    }

    private static func hasInheritanceSurface(
        thickClients: [String],
        interpreters: [String],
        electronHelpers: [String]
    ) -> Bool {
        !thickClients.isEmpty && (!interpreters.isEmpty || !electronHelpers.isEmpty)
    }
}
