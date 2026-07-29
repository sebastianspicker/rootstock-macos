import Foundation
import Darwin
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

/// Discovered applications plus recoverable traversal or budget failures.
struct AppDiscoveryResult {
    let applications: [DiscoveredApp]
    let errors: [CollectionError]
}

/// Finite scan budgets for untrusted application-directory contents.
struct AppDiscoveryLimits {
    let maximumEntries: Int
    let maximumInfoPlistBytes: Int
    let maximumInfoPlistBytesPerFile: Int

    init(
        maximumEntries: Int,
        maximumInfoPlistBytes: Int,
        maximumInfoPlistBytesPerFile: Int? = nil
    ) {
        self.maximumEntries = maximumEntries
        self.maximumInfoPlistBytes = maximumInfoPlistBytes
        self.maximumInfoPlistBytesPerFile = maximumInfoPlistBytesPerFile
            ?? maximumInfoPlistBytes
    }

    static let `default` = AppDiscoveryLimits(
        maximumEntries: 10_000,
        maximumInfoPlistBytes: 16 * 1024 * 1024,
        maximumInfoPlistBytesPerFile: 1024 * 1024
    )
}

private final class AppDiscoveryBudget {
    private var remainingEntries: Int
    private var remainingInfoPlistBytes: Int

    init(limits: AppDiscoveryLimits) {
        remainingEntries = limits.maximumEntries
        remainingInfoPlistBytes = limits.maximumInfoPlistBytes
    }

    func consumeEntry() -> Bool {
        guard remainingEntries > 0 else { return false }
        remainingEntries -= 1
        return true
    }

    func consumeAcceptedInfoPlistBytes(_ count: Int) -> Bool {
        guard count >= 0, count <= remainingInfoPlistBytes else { return false }
        remainingInfoPlistBytes -= count
        return true
    }
}

private enum InfoPlistOpenResult {
    case success(Int32)
    case failure(CollectionError)
}

/// Scans configured directories for installed .app bundles.
struct AppDiscovery {
    private let fileManager = FileManager.default
    private let directories: [URL]
    private let limits: AppDiscoveryLimits

    private static var defaultDirectories: [URL] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return [
            URL(fileURLWithPath: "/Applications"),
            URL(fileURLWithPath: home + "/Applications"),
            URL(fileURLWithPath: "/System/Applications"),
            URL(fileURLWithPath: "/System/Applications/Utilities"),
        ]
    }

    /// Default initializer - scans the standard macOS application directories.
    init() {
        directories = Self.defaultDirectories
        limits = .default
    }

    /// Testable initializer with injectable directory list.
    init(additionalDirectories: [URL]) {
        directories = Self.defaultDirectories + additionalDirectories
        limits = .default
    }

    /// Test-only initializer that isolates discovery and its finite budgets.
    init(directories: [URL], limits: AppDiscoveryLimits) {
        self.directories = directories
        self.limits = limits
    }

    /// Discover all .app bundles across configured directories.
    /// Scans the directory directly, plus one level into any subdirectories.
    func discover() -> AppDiscoveryResult {
        var apps: [DiscoveredApp] = []
        var errors: [CollectionError] = []
        var seen = Set<String>()
        let budget = AppDiscoveryBudget(limits: limits)

        for dir in directories.sorted(by: { $0.path < $1.path }) {
            let result = scanDirectory(dir, budget: budget)
            errors.append(contentsOf: result.errors)
            for app in result.applications where seen.insert(app.path).inserted {
                apps.append(app)
            }
        }

        return AppDiscoveryResult(applications: apps, errors: errors)
    }

    // MARK: - Private

    private func scanDirectory(_ dir: URL, budget: AppDiscoveryBudget) -> AppDiscoveryResult {
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

        var traversalErrors: [CollectionError] = []
        guard let enumerator = fileManager.enumerator(
            at: dir,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles],
            errorHandler: { url, error in
                traversalErrors.append(CollectionError(
                    source: "Entitlements",
                    message: "Failed to scan application subdirectory \(url.path): \(error.localizedDescription)",
                    recoverable: true
                ))
                return true
            }
        ) else {
            return AppDiscoveryResult(
                applications: [],
                errors: [CollectionError(
                    source: "Entitlements",
                    message: "Failed to scan application directory \(dir.path)",
                    recoverable: true
                )]
            )
        }

        var scanErrors: [CollectionError] = []
        let found = scanItems(from: enumerator, budget: budget, errors: &scanErrors)
        return AppDiscoveryResult(
            applications: found,
            errors: traversalErrors + scanErrors
        )
    }

    private func scanItems(
        from enumerator: FileManager.DirectoryEnumerator,
        budget: AppDiscoveryBudget,
        errors: inout [CollectionError]
    ) -> [DiscoveredApp] {
        var candidates: [URL] = []
        while let item = enumerator.nextObject() as? URL {
            guard budget.consumeEntry() else {
                errors.append(CollectionError(
                    source: "Entitlements",
                    message: "Stopped application discovery after reaching the \(limits.maximumEntries)-entry scan limit",
                    recoverable: true
                ))
                break
            }

            if item.pathExtension == "app" {
                enumerator.skipDescendants()
                candidates.append(item)
            } else if enumerator.level >= 2 {
                // Direct children are level 1. Descend through those containers,
                // then stop so discovery remains bounded to exactly one nested level.
                enumerator.skipDescendants()
            }
        }

        var found: [DiscoveredApp] = []
        for candidate in candidates.sorted(by: { $0.path < $1.path }) {
            appendDiscoveredApp(
                at: candidate,
                budget: budget,
                to: &found,
                errors: &errors
            )
        }
        return found
    }

    private func appendDiscoveredApp(
        at url: URL,
        budget: AppDiscoveryBudget,
        to found: inout [DiscoveredApp],
        errors: inout [CollectionError]
    ) {
        let result = makeDiscoveredApp(at: url, budget: budget)
        if let app = result.application {
            found.append(app)
        }
        if let error = result.error {
            errors.append(error)
        }
    }

    private func makeDiscoveredApp(
        at url: URL,
        budget: AppDiscoveryBudget
    ) -> (application: DiscoveredApp?, error: CollectionError?) {
        // Resolve symlinks (e.g. Homebrew Cask apps) before reading any file content.
        let resolvedURL = url.resolvingSymlinksInPath()

        let contentsURL = resolvedURL.appendingPathComponent("Contents")
        let plistResult = readInfoPlist(for: url, contentsURL: contentsURL, budget: budget)
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
        contentsURL: URL,
        budget: AppDiscoveryBudget
    ) -> (plist: [String: Any]?, error: CollectionError?) {
        let plistURL = contentsURL.appendingPathComponent("Info.plist")
        let descriptor: Int32
        switch openRegularInfoPlist(at: plistURL, for: originalURL) {
        case .success(let openedDescriptor):
            descriptor = openedDescriptor
        case .failure(let error):
            return (nil, error)
        }
        defer { Darwin.close(descriptor) }

        let plistData: Data
        do {
            guard let data = try readBoundedInfoPlistData(
                descriptor: descriptor,
                maximumBytes: limits.maximumInfoPlistBytesPerFile
            ) else {
                return (nil, CollectionError(
                    source: "Entitlements",
                    message: "Skipping \(originalURL.path): Info.plist exceeds the \(limits.maximumInfoPlistBytesPerFile)-byte per-file discovery budget",
                    recoverable: true
                ))
            }
            guard budget.consumeAcceptedInfoPlistBytes(data.count) else {
                return (nil, CollectionError(
                    source: "Entitlements",
                    message: "Skipping \(originalURL.path): Info.plist exceeds the remaining aggregate \(limits.maximumInfoPlistBytes)-byte discovery budget",
                    recoverable: true
                ))
            }
            plistData = data
        } catch {
            return (nil, CollectionError(
                source: "Entitlements",
                message: "Skipping \(originalURL.path): Info.plist missing or unreadable (\(error.localizedDescription))",
                recoverable: true
            ))
        }

        return parseInfoPlist(plistData, for: originalURL)
    }

    private func openRegularInfoPlist(
        at plistURL: URL,
        for originalURL: URL
    ) -> InfoPlistOpenResult {
        let descriptor = plistURL.path.withCString {
            Darwin.open($0, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        }
        guard descriptor >= 0 else {
            let detail = String(cString: strerror(errno))
            return .failure(CollectionError(
                source: "Entitlements",
                message: "Skipping \(originalURL.path): Info.plist missing or unreadable (\(detail))",
                recoverable: true
            ))
        }

        var fileStatus = stat()
        guard Darwin.fstat(descriptor, &fileStatus) == 0 else {
            let detail = String(cString: strerror(errno))
            Darwin.close(descriptor)
            return .failure(CollectionError(
                source: "Entitlements",
                message: "Skipping \(originalURL.path): Info.plist missing or unreadable (\(detail))",
                recoverable: true
            ))
        }
        guard fileStatus.st_mode & S_IFMT == S_IFREG else {
            Darwin.close(descriptor)
            return .failure(CollectionError(
                source: "Entitlements",
                message: "Skipping \(originalURL.path): Info.plist is not a regular file",
                recoverable: true
            ))
        }
        return .success(descriptor)
    }

    /// Reads from one already-validated descriptor so pathname replacement cannot
    /// bypass the independent per-file limit. A nil result means that limit was exceeded.
    private func readBoundedInfoPlistData(
        descriptor: Int32,
        maximumBytes: Int
    ) throws -> Data? {
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        var data = Data()
        let boundedMaximum = max(0, maximumBytes)

        while true {
            let remaining = boundedMaximum - data.count
            let budgetProbeSize = remaining == Int.max ? Int.max : remaining + 1
            let readSize = min(64 * 1024, budgetProbeSize)
            guard let chunk = try file.read(upToCount: readSize), !chunk.isEmpty else {
                return data
            }
            guard chunk.count <= remaining else {
                return nil
            }
            data.append(chunk)
        }
    }

    private func parseInfoPlist(
        _ data: Data,
        for originalURL: URL
    ) -> (plist: [String: Any]?, error: CollectionError?) {
        do {
            guard let parsed = try PropertyListSerialization.propertyList(
                from: data, options: [], format: nil
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
