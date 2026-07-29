import Foundation
import RootstockCore
import RootstockMacFacts

/// Shared launchd plist enumeration helpers backed by `LaunchdPlistFacts`.
enum LaunchPlistSupport {
    struct FileMeta {
        let exists: Bool
        let size: Int64?
        let mtime: Date?
    }
    static func enumeratePlists(in directory: URL) -> [LaunchAgentEntry] {
        LaunchdPlistFacts.listPlistPaths(in: directory.path)
            .map { parseLaunchPlist(at: URL(fileURLWithPath: $0)) }
            .sorted { $0.path < $1.path }
    }

    static func parseLaunchPlist(at url: URL) -> LaunchAgentEntry {
        let summary = LaunchdPlistFacts.summarize(plistPath: url.path)
        return LaunchAgentEntry(
            label: summary.label,
            path: url.path,
            programArguments: summary.effectiveArguments
        )
    }

    static func directorySizeBytes(at url: URL) -> Int64? {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(
            at: url,
            includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            return nil
        }
        var total: Int64 = 0
        for case let fileURL as URL in enumerator {
            guard
                let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
                values.isRegularFile == true,
                let size = values.fileSize
            else { continue }
            total += Int64(size)
        }
        return total
    }

    static func fileMeta(at path: String) -> FileMeta {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        let exists = fm.fileExists(atPath: path, isDirectory: &isDir)
        guard exists, !isDir.boolValue else {
            return FileMeta(exists: exists, size: nil, mtime: nil)
        }
        let url = URL(fileURLWithPath: path)
        let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])
        let size = values?.fileSize.map { Int64($0) }
        return FileMeta(exists: true, size: size, mtime: values?.contentModificationDate)
    }
}
