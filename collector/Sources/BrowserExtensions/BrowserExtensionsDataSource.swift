import Foundation
import HostCommand
import Models

/// Inventories browser extensions in Chromium-family browsers, Firefox and Safari.
///
/// Reads manifests and profile settings from the current user's
/// `~/Library/Application Support`, and asks `pluginkit` for Safari extensions.
/// Only metadata is read: no browsing data, cookies or extension storage.
public struct BrowserExtensionsDataSource: DataSource {
    public let name = "Browser Extensions"
    public let requiresElevation = false

    static let maxExtensions = 500
    static let pluginkitPath = "/usr/bin/pluginkit"

    private let applicationSupport: String
    private let access: BrowserFileAccess
    private let runCommand: ShellCommand

    public init() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        self.applicationSupport = "\(home)/Library/Application Support"
        self.access = .live
        self.runCommand = { path, arguments, timeout in
            ShellCommandRunner.run(path, arguments, timeout)
        }
    }

    init(applicationSupport: String, access: BrowserFileAccess, runCommand: @escaping ShellCommand) {
        self.applicationSupport = applicationSupport
        self.access = access
        self.runCommand = runCommand
    }

    public func collect() async -> DataSourceResult {
        var result = BrowserReadResult()
        for browser in ChromiumBrowser.all {
            let root = "\(applicationSupport)/\(browser.relativeRoot)"
            result.append(ChromiumExtensionReader.read(browser: browser, root: root, access: access))
        }
        result.append(FirefoxExtensionReader.read(
            profilesRoot: "\(applicationSupport)/Firefox/Profiles",
            access: access
        ))
        result.append(readSafari())

        var errors = result.errors.map { CollectionError(source: name, message: $0, recoverable: true) }
        let sorted = Self.sorted(result.extensions)
        if sorted.count > Self.maxExtensions {
            errors.append(CollectionError(
                source: name,
                message: "Browser extension inventory truncated to \(Self.maxExtensions) of \(sorted.count) extensions",
                recoverable: true
            ))
        }
        return DataSourceResult(nodes: Array(sorted.prefix(Self.maxExtensions)), errors: errors)
    }

    private func readSafari() -> BrowserReadResult {
        var result = BrowserReadResult()
        var seen = Set<String>()
        for protocolName in SafariExtensionReader.protocols {
            let outcome = runCommand(Self.pluginkitPath, ["-mAvvv", "-p", protocolName], Shell.defaultTimeoutSeconds)
            guard case .success(let output) = outcome else {
                result.errors.append(
                    "pluginkit -mAvvv -p \(protocolName) failed: \(outcome.failureDescription ?? "unknown failure")"
                )
                continue
            }
            let extensions = SafariExtensionReader.parsePluginkitOutput(output.stdout)
            result.extensions.append(contentsOf: extensions.filter { seen.insert($0.extensionId).inserted })
        }
        return result
    }

    /// Stable order: browser, profile, extension id.
    static func sorted(_ extensions: [BrowserExtension]) -> [BrowserExtension] {
        extensions.sorted {
            ($0.browser.rawValue, $0.profile, $0.extensionId) < ($1.browser.rawValue, $1.profile, $1.extensionId)
        }
    }
}
