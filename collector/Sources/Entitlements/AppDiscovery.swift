import Foundation

/// Represents a discovered .app bundle before entitlement extraction.
struct DiscoveredApp {
    let name: String
    let bundleId: String
    let path: String
    let version: String?
    let executablePath: String
    let isElectron: Bool
    let isSystem: Bool
}

/// Scans configured directories for installed .app bundles.
struct AppDiscovery {
    private let fileManager = FileManager.default
    private let directories: [URL]

    private static var defaultDirectories: [URL] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return [
            URL(fileURLWithPath: "/Applications"),
            URL(fileURLWithPath: home + "/Applications"),
            URL(fileURLWithPath: "/System/Applications"),
            URL(fileURLWithPath: "/System/Applications/Utilities"),
        ]
    }

    /// Default initializer — scans the standard macOS application directories.
    init() {
        directories = Self.defaultDirectories
    }

    /// Testable initializer with injectable directory list.
    init(additionalDirectories: [URL]) {
        directories = Self.defaultDirectories + additionalDirectories
    }

    /// Discover all .app bundles across configured directories.
    /// Scans the directory directly, plus one level into any subdirectories.
    func discover() -> [DiscoveredApp] {
        var apps: [DiscoveredApp] = []
        var seen = Set<String>()

        for dir in directories {
            for app in scanDirectory(dir) {
                if seen.insert(app.path).inserted {
                    apps.append(app)
                }
            }
        }

        return apps
    }

    // MARK: - Private

    private func scanDirectory(_ dir: URL) -> [DiscoveredApp] {
        guard let contents = try? fileManager.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) else { return [] }

        var found: [DiscoveredApp] = []

        for item in contents {
            if item.pathExtension == "app" {
                if let app = makeDiscoveredApp(at: item) {
                    found.append(app)
                }
            } else {
                // One level deeper into subdirectories
                guard (try? item.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
                else { continue }
                guard let subContents = try? fileManager.contentsOfDirectory(
                    at: item,
                    includingPropertiesForKeys: [.isDirectoryKey],
                    options: [.skipsHiddenFiles]
                ) else { continue }
                for subItem in subContents where subItem.pathExtension == "app" {
                    if let app = makeDiscoveredApp(at: subItem) {
                        found.append(app)
                    }
                }
            }
        }

        return found
    }

    private func makeDiscoveredApp(at url: URL) -> DiscoveredApp? {
        // Resolve symlinks (e.g. Homebrew Cask apps) before reading any file content.
        let resolvedURL = url.resolvingSymlinksInPath()

        let contentsURL = resolvedURL.appendingPathComponent("Contents")
        let plistURL = contentsURL.appendingPathComponent("Info.plist")

        // Operate directly; try? handles missing/unreadable plist without TOCTOU race.
        guard let plistData = try? Data(contentsOf: plistURL),
              let plist = try? PropertyListSerialization.propertyList(
                  from: plistData, options: [], format: nil
              ) as? [String: Any]
        else { return nil }

        // Use path-based fallback bundle ID when CFBundleIdentifier is absent or empty.
        let bundleId: String
        if let id = plist["CFBundleIdentifier"] as? String, !id.isEmpty {
            bundleId = id
        } else {
            // Derive a stable pseudo-ID from the bundle path so the app is still indexed.
            bundleId = "path.\(resolvedURL.deletingPathExtension().lastPathComponent)"
        }

        let name = (plist["CFBundleName"] as? String)
            ?? (plist["CFBundleDisplayName"] as? String)
            ?? resolvedURL.deletingPathExtension().lastPathComponent

        let version = plist["CFBundleShortVersionString"] as? String
        let execName = plist["CFBundleExecutable"] as? String ?? name
        let execURL = contentsURL.appendingPathComponent("MacOS").appendingPathComponent(execName)

        guard fileManager.fileExists(atPath: execURL.path) else { return nil }

        let isElectron = detectElectron(contentsURL: contentsURL)
        // Use the original (pre-symlink) path for reporting; resolved path for file I/O.
        let isSystem = resolvedURL.path.hasPrefix("/System/") || resolvedURL.path.hasPrefix("/usr/")

        return DiscoveredApp(
            name: name,
            bundleId: bundleId,
            path: url.path,                 // original path (symlink or direct)
            version: version,
            executablePath: execURL.path,   // resolved path for codesign / Security.framework
            isElectron: isElectron,
            isSystem: isSystem
        )
    }

    /// Detects Electron apps by checking for the Electron Framework bundle.
    private func detectElectron(contentsURL: URL) -> Bool {
        let frameworksURL = contentsURL.appendingPathComponent("Frameworks")
        return fileManager.fileExists(
            atPath: frameworksURL.appendingPathComponent("Electron Framework.framework").path
        ) || fileManager.fileExists(
            atPath: frameworksURL.appendingPathComponent("Squirrel.framework").path
        )
    }
}
