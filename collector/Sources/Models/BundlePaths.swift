import Foundation

/// Path rules for files inside application bundles.
public enum BundlePaths {
    /// Absolute path of the bundle's main executable (`Contents/MacOS/<executableName>`),
    /// or nil when the name is empty, `.`/`..`, or contains `/` and could escape the bundle.
    public static func executablePath(bundle: String, executableName: String) -> String? {
        guard isSafeComponent(executableName) else { return nil }
        let macOS = (bundle as NSString).appendingPathComponent("Contents/MacOS")
        return (macOS as NSString).appendingPathComponent(executableName)
    }

    /// True when `name` is a single path component that stays inside its parent directory.
    public static func isSafeComponent(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && !name.contains("/") && !name.contains("\0")
    }

    /// Application path (as recorded and symlink-resolved) to bundle id. Full `.app` paths
    /// only, never short names, so two apps with one executable name cannot collide.
    public static func bundleIdMap(_ applications: [Application]) -> [String: String] {
        var pathToBundle: [String: String] = [:]
        for app in applications {
            pathToBundle[app.path] = app.bundleId
            pathToBundle[URL(fileURLWithPath: app.path).resolvingSymlinksInPath().path] = app.bundleId
        }
        return pathToBundle
    }

    /// Bundle id for a process path: an exact app path, or the app that contains it (`.app/`).
    public static func bundleId(forCommand command: String, in pathToBundle: [String: String]) -> String? {
        if let bundleId = pathToBundle[command] { return bundleId }
        guard let appRange = command.range(of: ".app/") else { return nil }
        return pathToBundle[String(command[..<appRange.upperBound].dropLast())]
    }
}
