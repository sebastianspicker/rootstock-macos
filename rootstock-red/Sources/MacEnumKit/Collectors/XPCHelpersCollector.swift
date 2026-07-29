import Foundation
import RootstockCore

/// Filenames only under `/Library/PrivilegedHelperTools` (no binary analysis).
public struct XPCHelpersCollector: Collector {
    public static let id = "collect.xpc_helpers"
    public static let cost: CollectorCost = .medium

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let root = URL(fileURLWithPath: "/Library/PrivilegedHelperTools", isDirectory: true)
        let fm = FileManager.default
        var names: [String] = []
        var note: String

        var isDir: ObjCBool = false
        if !fm.fileExists(atPath: root.path, isDirectory: &isDir) {
            note = "path absent"
        } else if let contents = try? fm.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) {
            names = contents
                .map(\.lastPathComponent)
                .filter { !$0.hasPrefix(".") }
                .sorted()
            note = "filenames only (\(names.count))"
        } else {
            note = "directory present but listing denied"
        }

        var state = CollectedState()
        state.privilegedHelperTools = names
        state.collectorNotes[Self.id] = note
        return state
    }
}
