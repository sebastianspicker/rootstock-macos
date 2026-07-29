import Foundation
import RootstockCore

/// ClickFix / paste-and-run Terminal delivery posture (Wave-8).
///
/// Research basis: Microsoft/Jamf ClickFix campaign research; TerminalFix paste-run class.
/// Safety and behavior: typed `ClickFixTerminalDeliveryState`; never builds lures or payloads.
public struct ClickFixTerminalDeliveryCollector: Collector {
    public static let id = "collect.clickfix_terminal_delivery"
    public static let cost: CollectorCost = .low

    private static let terminalPaths: [String] = [
        "/System/Applications/Utilities/Terminal.app",
        "/Applications/Utilities/Terminal.app",
        "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
        "/bin/zsh",
        "/bin/bash",
        "/bin/sh",
    ]

    private static let scriptEditorPaths: [String] = [
        "/System/Applications/Utilities/Script Editor.app",
        "/Applications/Utilities/Script Editor.app",
        "/System/Applications/Utilities/Script Editor.app/Contents/MacOS/Script Editor",
        "/usr/bin/osascript",
        "/System/Library/Frameworks/AppleScriptKit.framework",
        "/System/Library/Frameworks/AppleScriptObjC.framework",
    ]

    private static let loaderPaths: [String] = [
        "/usr/bin/curl",
        "/usr/bin/osascript",
        "/usr/bin/python3",
        "/usr/bin/ruby",
        "/bin/zsh",
        "/bin/bash",
    ]

    private static let pasteWarningHints: [String] = [
        NSHomeDirectory() + "/Library/Preferences/com.apple.Terminal.plist",
        "/Library/Preferences/com.apple.Terminal.plist",
        "/System/Library/PreferencePanes",
        "/System/Applications/Utilities/Terminal.app/Contents/Info.plist",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "ClickFix delivery surface: Terminal/Script Editor/loader path presence - never builds lures",
        ]

        var terminal: [String] = []
        for path in Self.terminalPaths where fm.fileExists(atPath: path) {
            terminal.append(path)
            notes.append("terminal_or_shell: \(path)")
        }

        var scriptEditor: [String] = []
        for path in Self.scriptEditorPaths where fm.fileExists(atPath: path) {
            scriptEditor.append(path)
            notes.append("script_editor_or_applescript: \(path)")
        }

        var loaders: [String] = []
        for path in Self.loaderPaths where fm.fileExists(atPath: path) {
            loaders.append(path)
            notes.append("loader_binary: \(path)")
        }

        var pasteHints: [String] = []
        for path in Self.pasteWarningHints where fm.fileExists(atPath: path) {
            pasteHints.append(path)
            notes.append("paste_warning_hint: \(path)")
        }

        terminal = Array(Set(terminal)).sorted()
        scriptEditor = Array(Set(scriptEditor)).sorted()
        loaders = Array(Set(loaders)).sorted()
        pasteHints = Array(Set(pasteHints)).sorted()

        let surface = !terminal.isEmpty || !scriptEditor.isEmpty || loaders.count >= 2

        var state = CollectedState()
        state.clickFixTerminalDelivery = ClickFixTerminalDeliveryState(
            terminalAppPaths: terminal,
            scriptEditorPaths: scriptEditor,
            loaderBinaryPaths: loaders,
            pasteWarningHints: pasteHints,
            deliverySurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "terminal=\(terminal.count) scriptEditor=\(scriptEditor.count) "
            + "loaders=\(loaders.count) pasteHints=\(pasteHints.count) surface=\(surface)"
        return state
    }
}
