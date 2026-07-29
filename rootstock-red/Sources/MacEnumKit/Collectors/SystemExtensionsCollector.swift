import Foundation
import RootstockCore

/// Inventory of `/Library/SystemExtensions` when readable.
public struct SystemExtensionsCollector: Collector {
    public static let id = "collect.system_extensions"
    public static let cost: CollectorCost = .medium

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let root = URL(fileURLWithPath: "/Library/SystemExtensions", isDirectory: true)
        let fm = FileManager.default
        var paths: [String] = []
        var note: String

        var isDir: ObjCBool = false
        if !fm.fileExists(atPath: root.path, isDirectory: &isDir) {
            note = "path absent"
        } else if !isDir.boolValue {
            note = "path exists but is not a directory"
        } else if let contents = try? fm.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) {
            // Prefer nested extension-ish entries; fall back to top-level names.
            for item in contents.sorted(by: { $0.path < $1.path }) {
                if item.pathExtension == "systemextension" {
                    paths.append(item.path)
                } else if let nested = try? fm.contentsOfDirectory(
                    at: item,
                    includingPropertiesForKeys: nil,
                    options: [.skipsHiddenFiles]
                ) {
                    let sysExts = nested.filter { $0.pathExtension == "systemextension" }
                    if sysExts.isEmpty {
                        paths.append(item.path)
                    } else {
                        paths.append(contentsOf: sysExts.map(\.path))
                    }
                } else {
                    paths.append(item.path)
                }
            }
            note = "listed \(paths.count) entries"
        } else {
            note = "directory present but listing denied"
        }

        var state = CollectedState()
        state.systemExtensionPaths = paths
        state.collectorNotes[Self.id] = note
        return state
    }
}
