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
}
