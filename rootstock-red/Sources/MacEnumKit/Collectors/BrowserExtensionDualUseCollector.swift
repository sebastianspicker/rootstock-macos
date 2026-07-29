import Foundation
import RootstockCore

/// Browser extension dual-use persistence / collection plane (Wave-11).
///
/// Research basis: Chromium/Safari extension persistence and broad-permission collection research.
/// Safety and behavior: multi-browser path plane + compound with FDA/remote; never dumps extension storage secrets.
public struct BrowserExtensionDualUseCollector: Collector {
    public static let id = "collect.browser_extension_dualuse"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let home = NSHomeDirectory()
        var notes = ["Browser extension dual-use plane: path presence only - never dumps extension secrets or cookies"]
        let chromium = existingPaths(Self.chromiumRoots(home), notePrefix: "chromium_extensions", notes: &notes)
        let safari = existingPaths(Self.safariRoots(home), notePrefix: "safari_extensions", notes: &notes)
        let prefs = existingPaths(Self.preferencePaths(home), notePrefix: "extension_pref", notes: &notes)
        let surface = chromium.count + safari.count >= 1 || prefs.count >= 2
        var state = CollectedState()
        state.browserExtensionDualUse = BrowserExtensionDualUseState(chromiumExtensionPaths: chromium, safariExtensionPaths: safari, preferencePaths: prefs, extensionSurfacePresent: surface, notes: notes)
        state.collectorNotes[Self.id] = "chromium=\(chromium.count) safari=\(safari.count) prefs=\(prefs.count) surface=\(surface)"
        return state
    }


    private static func chromiumRoots(_ home: String) -> [String] {
        [
            home + "/Library/Application Support/Google/Chrome/Default/Extensions",
            home + "/Library/Application Support/Google/Chrome/Profile 1/Extensions",
            home + "/Library/Application Support/Chromium/Default/Extensions",
            home + "/Library/Application Support/Microsoft Edge/Default/Extensions",
            home + "/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions",
            home + "/Library/Application Support/Arc/User Data/Default/Extensions",
        ]
    }

    private static func safariRoots(_ home: String) -> [String] {
        [
            home + "/Library/Safari/Extensions",
            home + "/Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions",
            home + "/Library/Containers/com.apple.Safari/Data/Library/Safari/WebExtensions",
            "/Applications/Safari.app",
        ]
    }

    private static func preferencePaths(_ home: String) -> [String] {
        [
            home + "/Library/Application Support/Google/Chrome/Default/Preferences",
            home + "/Library/Application Support/Google/Chrome/Default/Secure Preferences",
            home + "/Library/Preferences/com.apple.Safari.plist",
            home + "/Library/Preferences/com.apple.Safari.Extensions.plist",
        ]
    }

    private func existingPaths(_ paths: [String], notePrefix: String, notes: inout [String]) -> [String] {
        let existing = paths.filter { FileManager.default.fileExists(atPath: $0) }
        notes.append(contentsOf: existing.map { "\(notePrefix): \($0)" })
        return Array(Set(existing)).sorted()
    }
}
