import Foundation
import Models

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

struct AppDiscoveryResult {
    let applications: [DiscoveredApp]
    let errors: [CollectionError]
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
    func discover() -> AppDiscoveryResult {
        var apps: [DiscoveredApp] = []
        var errors: [CollectionError] = []
        var seen = Set<String>()

        for dir in directories {
            let result = scanDirectory(dir)
            errors.append(contentsOf: result.errors)
            for app in result.applications where seen.insert(app.path).inserted {
                apps.append(app)
            }
        }

        return AppDiscoveryResult(applications: apps, errors: errors)
    }

    // MARK: - Private

    private func scanDirectory(_ dir: URL) -> AppDiscoveryResult {
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: dir.path, isDirectory: &isDirectory) else {
            return AppDiscoveryResult(applications: [], errors: [])
        }
        guard isDirectory.boolValue else {
            return AppDiscoveryResult(
                applications: [],
                errors: [CollectionError(
                    source: "Entitlements",
                    message: "Application scan path is not a directory \(dir.path)",
                    recoverable: true
                )]
            )
        }

        let contents: [URL]
        do {
            contents = try fileManager.contentsOfDirectory(
                at: dir,
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles]
            )
        } catch {
            return AppDiscoveryResult(
                applications: [],
                errors: [CollectionError(
                    source: "Entitlements",
                    message: "Failed to scan application directory \(dir.path): \(error.localizedDescription)",
                    recoverable: true
                )]
            )
        }

        var found: [DiscoveredApp] = []
        var errors: [CollectionError] = []

        for item in contents {
            if item.pathExtension == "app" {
                appendDiscoveredApp(at: item, to: &found, errors: &errors)
            } else {
                scanNestedApps(in: item, found: &found, errors: &errors)
            }
        }

        return AppDiscoveryResult(applications: found, errors: errors)
    }

    private func scanNestedApps(in directory: URL, found: inout [DiscoveredApp], errors: inout [CollectionError]) {
        // One level deeper into subdirectories.
        guard (try? directory.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true else {
            return
        }

        let subContents: [URL]
        do {
            subContents = try fileManager.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles]
            )
        } catch {
            errors.append(CollectionError(
                source: "Entitlements",
                message: "Failed to scan application subdirectory \(directory.path): \(error.localizedDescription)",
                recoverable: true
            ))
            return
        }

        for subItem in subContents where subItem.pathExtension == "app" {
            appendDiscoveredApp(at: subItem, to: &found, errors: &errors)
        }
    }

    private func appendDiscoveredApp(
        at url: URL,
        to found: inout [DiscoveredApp],
        errors: inout [CollectionError]
    ) {
        let result = makeDiscoveredApp(at: url)
        if let app = result.application {
            found.append(app)
        }
        if let error = result.error {
            errors.append(error)
        }
    }

    private func makeDiscoveredApp(at url: URL) -> (application: DiscoveredApp?, error: CollectionError?) {
        // Resolve symlinks (e.g. Homebrew Cask apps) before reading any file content.
        let resolvedURL = url.resolvingSymlinksInPath()

        let contentsURL = resolvedURL.appendingPathComponent("Contents")
        let plistResult = readInfoPlist(for: url, contentsURL: contentsURL)
        guard let plist = plistResult.plist else {
            return (nil, plistResult.error)
        }

        // Use path-based fallback bundle ID when CFBundleIdentifier is absent or empty.
        let bundleId = bundleIdentifier(from: plist, resolvedURL: resolvedURL)
        let name = applicationName(from: plist, resolvedURL: resolvedURL)
        let version = plist["CFBundleShortVersionString"] as? String
        let execName = plist["CFBundleExecutable"] as? String ?? name
        let execURL = contentsURL.appendingPathComponent("MacOS").appendingPathComponent(execName)

        guard fileManager.fileExists(atPath: execURL.path) else {
            return (nil, CollectionError(
                source: "Entitlements",
                message: "Skipping \(url.path): executable missing at \(execURL.path)",
                recoverable: true
            ))
        }

        let isElectron = detectElectron(contentsURL: contentsURL)
        // Use the original (pre-symlink) path for reporting; resolved path for file I/O.
        let isSystem = resolvedURL.path.hasPrefix("/System/") || resolvedURL.path.hasPrefix("/usr/")

        return (DiscoveredApp(
            name: name,
            bundleId: bundleId,
            path: url.path,                 // original path (symlink or direct)
            version: version,
            executablePath: execURL.path,   // resolved path for codesign / Security.framework
            isElectron: isElectron,
            isSystem: isSystem
        ), nil)
    }

    private func readInfoPlist(
        for originalURL: URL,
        contentsURL: URL
    ) -> (plist: [String: Any]?, error: CollectionError?) {
        let plistURL = contentsURL.appendingPathComponent("Info.plist")

        let plistData: Data
        do {
            plistData = try Data(contentsOf: plistURL)
        } catch {
            return (nil, CollectionError(
                source: "Entitlements",
                message: "Skipping \(originalURL.path): Info.plist missing or unreadable (\(error.localizedDescription))",
                recoverable: true
            ))
        }

        do {
            guard let parsed = try PropertyListSerialization.propertyList(
                from: plistData, options: [], format: nil
            ) as? [String: Any] else {
                return (nil, CollectionError(
                    source: "Entitlements",
                    message: "Skipping \(originalURL.path): Info.plist is not a dictionary",
                    recoverable: true
                ))
            }
            return (parsed, nil)
        } catch {
            return (nil, CollectionError(
                source: "Entitlements",
                message: "Skipping \(originalURL.path): malformed Info.plist (\(error.localizedDescription))",
                recoverable: true
            ))
        }
    }

    private func bundleIdentifier(from plist: [String: Any], resolvedURL: URL) -> String {
        if let id = plist["CFBundleIdentifier"] as? String, !id.isEmpty {
            return id
        }

        // Derive a stable pseudo-ID from the bundle path so the app is still indexed.
        return "path.\(resolvedURL.deletingPathExtension().lastPathComponent)"
    }

    private func applicationName(from plist: [String: Any], resolvedURL: URL) -> String {
        (plist["CFBundleName"] as? String)
            ?? (plist["CFBundleDisplayName"] as? String)
            ?? resolvedURL.deletingPathExtension().lastPathComponent
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
