import Foundation
import HostCommand
import LaunchdPlists
import Models

/// Launchd jobs and login items shipped inside application bundles
/// (`Contents/Library/LaunchAgents`, `LaunchDaemons`, `LoginItems`).
extension PersistenceDataSource {
    /// A login-item helper bundle found under `Contents/Library/LoginItems`.
    struct EmbeddedLoginItem: Equatable {
        let helperPath: String
        let bundleId: String
        let program: String?
    }

    func collectEmbeddedItems(loadedState: LaunchctlLoadedState) -> ([LaunchItem], [String]) {
        var items: [LaunchItem] = []
        var errors: [String] = []
        let appPaths = Set(knownApps.map(\.path)).filter { !$0.hasPrefix("/System/") }.sorted()
        for appPath in appPaths {
            let library = (appPath as NSString).appendingPathComponent("Contents/Library")
            for (subdirectory, type) in [("LaunchAgents", LaunchItem.ItemType.agent), ("LaunchDaemons", .daemon)] {
                let directory = (library as NSString).appendingPathComponent(subdirectory)
                guard !SymbolicLinks.isLink(atPath: directory) else { continue }
                let (entries, errs) = plistParser.parseDirectory(at: directory, skippingSymbolicLinks: true)
                items += entries.map { entry in
                    launchItemFrom(
                        entry.resolvingBundleProgram(in: appPath),
                        type: type,
                        loadedState: loadedState,
                        bundlePath: appPath
                    )
                }
                errors += errs
            }
            let loginItemsDir = (library as NSString).appendingPathComponent("LoginItems")
            items += Self.embeddedLoginItems(in: loginItemsDir).map {
                loginItem(from: $0, bundlePath: appPath)
            }
        }
        return (items, errors)
    }

    private func loginItem(from helper: EmbeddedLoginItem, bundlePath: String) -> LaunchItem {
        let facts = ProgramFacts(program: helper.program)
        return LaunchItem(
            label: helper.bundleId,
            path: helper.helperPath,
            type: .loginItem,
            program: helper.program,
            runAtLoad: false,
            user: nil,
            ownership: ownership(plistPath: helper.helperPath, program: helper.program),
            details: LaunchItem.Details(
                programExists: facts.exists,
                programSha256: facts.sha256,
                plistModified: FileTimestamp.modified(path: helper.helperPath),
                bundlePath: bundlePath
            )
        )
    }

    /// Helper `.app` bundles directly under `directory`, identified by their Info.plist.
    /// Missing or symlinked directories yield no entries, symlinked helpers are skipped, and
    /// helpers without a bundle id fall back to their name. A `CFBundleExecutable` that is
    /// not a plain file name leaves the helper without a program.
    static func embeddedLoginItems(
        in directory: String,
        fileManager: FileManager = .default
    ) -> [EmbeddedLoginItem] {
        guard !SymbolicLinks.isLink(atPath: directory),
              let names = try? fileManager.contentsOfDirectory(atPath: directory) else { return [] }
        return names.filter { $0.hasSuffix(".app") }.sorted().compactMap { name in
            let helperPath = (directory as NSString).appendingPathComponent(name)
            guard !SymbolicLinks.isLink(atPath: helperPath) else { return nil }
            let infoPath = (helperPath as NSString).appendingPathComponent("Contents/Info.plist")
            let info = (try? BoundedFileReader.read(path: infoPath)).flatMap(Shell.parsePlistDict(from:)) ?? [:]
            let bundleId = (info["CFBundleIdentifier"] as? String).flatMap { $0.isEmpty ? nil : $0 }
                ?? String(name.dropLast(4))
            let program = (info["CFBundleExecutable"] as? String).flatMap { executable in
                BundlePaths.executablePath(bundle: helperPath, executableName: executable)
            }
            return EmbeddedLoginItem(helperPath: helperPath, bundleId: bundleId, program: program)
        }
    }
}
