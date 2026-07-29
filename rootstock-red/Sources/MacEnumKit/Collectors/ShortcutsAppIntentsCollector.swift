import Foundation
import RootstockCore

/// Shortcuts / App Intents automation lateral posture (Wave-11).
///
/// Research basis: Shortcuts.app automation / App Intents 2024–26 lateral and execution research.
/// Safety and behavior: path inventory + remote amplifiers; never runs shortcuts or forges intents.
public struct ShortcutsAppIntentsCollector: Collector {
    public static let id = "collect.shortcuts_app_intents"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let home = NSHomeDirectory()
        var notes: [String] = [
            "Shortcuts / App Intents surface: path presence only - never runs shortcuts or forges App Intents",
        ]

        let shortcuts = existingPaths([
            "/System/Applications/Shortcuts.app",
            "/Applications/Shortcuts.app",
            home + "/Library/Shortcuts",
            home + "/Library/Shortcuts/Shortcuts.sqlite",
            home + "/Library/Containers/com.apple.shortcuts",
            home + "/Library/Group Containers/group.is.workflow.my.app",
            home + "/Library/Group Containers/group.is.workflow.shortcuts",
        ], fm: fm, notePrefix: "shortcuts", notes: &notes)

        let intents = intentPaths([
            "/System/Library/Frameworks/AppIntents.framework",
            "/System/Library/Frameworks/AppIntents.framework/AppIntents",
            "/System/Library/PrivateFrameworks/WorkflowKit.framework",
            "/System/Library/PrivateFrameworks/VoiceShortcutClient.framework",
            home + "/Library/Developer/Xcode/DerivedData",
        ], fm: fm, notes: &notes)

        let prefs = existingPaths([
            home + "/Library/Preferences/com.apple.shortcuts.plist",
            home + "/Library/Preferences/com.apple.siriactionsd.plist",
            home + "/Library/Preferences/com.apple.voicebankingd.plist",
            "/Library/Preferences/com.apple.shortcuts.plist",
        ], fm: fm, notePrefix: "automation_pref", notes: &notes)

        let surface = shortcuts.count >= 1 || intents.count >= 1

        var state = CollectedState()
        state.shortcutsAppIntents = ShortcutsAppIntentsState(
            shortcutsAppPaths: shortcuts,
            appIntentsPaths: intents,
            automationPrefPaths: prefs,
            automationSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "shortcuts=\(shortcuts.count) intents=\(intents.count) prefs=\(prefs.count) surface=\(surface)"
        return state
    }

    private func existingPaths(_ paths: [String], fm: FileManager, notePrefix: String, notes: inout [String]) -> [String] { let found = paths.filter { fm.fileExists(atPath: $0) }; found.forEach { notes.append("\(notePrefix): \($0)") }; return Array(Set(found)).sorted() }
    private func intentPaths(_ paths: [String], fm: FileManager, notes: inout [String]) -> [String] { let found = paths.filter { fm.fileExists(atPath: $0) }; let intents = found.filter { !$0.contains("DerivedData") }; found.filter { $0.contains("DerivedData") }.forEach { notes.append("developer_derived_data_present: \($0) (not counted as surface alone)") }; intents.forEach { notes.append("app_intents: \($0)") }; return Array(Set(intents)).sorted() }
}
