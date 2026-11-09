import Foundation
import RootstockCore

/// Absolute paths of the entries under `/Library/PrivilegedHelperTools` (no binary analysis).
public struct XPCHelpersCollector: Collector {
    public static let id = "collect.xpc_helpers"
    public static let cost: CollectorCost = .medium

    private let root: URL

    public init() {
        self.init(root: URL(fileURLWithPath: "/Library/PrivilegedHelperTools", isDirectory: true))
    }

    init(root: URL) {
        self.root = root
    }

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var paths: [String] = []
        var note: String

        var isDir: ObjCBool = false
        if !fm.fileExists(atPath: root.path, isDirectory: &isDir) {
            note = "path absent"
        } else if let contents = try? fm.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) {
            paths = contents
                .filter { !$0.lastPathComponent.hasPrefix(".") }
                .map(\.path)
                .sorted()
            note = "paths only (\(paths.count))"
        } else {
            note = "directory present but listing denied"
        }

        var state = CollectedState()
        state.privilegedHelperTools = paths
        state.collectorNotes[Self.id] = note
        return state
    }
}
