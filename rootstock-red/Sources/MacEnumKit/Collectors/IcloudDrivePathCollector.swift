import Foundation
import RootstockCore

/// iCloud Drive / Mobile Documents path plane (Wave-14).
/// Research basis: 2025–26 macOS iCloud Drive path plane tradecraft.
/// Safety and behavior: path inventory only; never enumerates iCloud file contents or exfiltrates Mobile Documents.
public struct IcloudDrivePathCollector: Collector {
    public static let id = "collect.icloud_drive_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["iCloud Drive path plane: path presence only - never enumerates iCloud file contents or exfiltrates Mobile Documents"]
        var a: [String] = []
        for path in [NSHomeDirectory() + "/Library/Mobile Documents",
            NSHomeDirectory() + "/Library/Mobile Documents/com~apple~CloudDocs"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Application Support/CloudDocs",
            NSHomeDirectory() + "/Library/Preferences/MobileMeAccounts.plist"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/PrivateFrameworks/CloudKit.framework",
            "/System/Library/PrivateFrameworks/CloudDocs.framework",
            "/usr/libexec/bird"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.icloudDrivePath = IcloudDrivePathState(
            mobileDocumentsPaths: a, icloudDrivePaths: b, cloudKitPaths: c,
            icloudPathSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
