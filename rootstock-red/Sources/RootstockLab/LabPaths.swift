import Foundation

/// Shared lab filesystem path helpers - single implementation for all lab actions.
public enum LabPaths: Sendable {
    /// Default lab root under the current user's home: `~/Library/RootstockLab`.
    public static let defaultRootRelativePath = "Library/RootstockLab"

    /// Resolve the lab root directory from request parameters.
    ///
    /// - Parameters:
    ///   - params: Request parameters; `labRoot` overrides the default when non-empty.
    ///   - subdirectory: Optional path component(s) appended under the default root only
    ///     (ignored when `labRoot` is explicitly provided). Use e.g. `"cron"` for
    ///     `~/Library/RootstockLab/cron`.
    public static func resolveLabRoot(
        params: [String: String],
        subdirectory: String? = nil
    ) -> URL {
        if let labRoot = params["labRoot"], !labRoot.isEmpty {
            return URL(fileURLWithPath: labRoot, isDirectory: true).standardizedFileURL
        }
        var url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(defaultRootRelativePath, isDirectory: true)
        if let subdirectory, !subdirectory.isEmpty {
            for component in subdirectory.split(separator: "/") where !component.isEmpty {
                url = url.appendingPathComponent(String(component), isDirectory: true)
            }
        }
        return url.standardizedFileURL
    }

    /// Sanitize a free-form string for use as a single path component.
    public static func sanitizePathComponent(
        _ raw: String,
        emptyDefault: String = "generic"
    ) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-"))
        let cleaned = raw.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" }
        let s = String(cleaned)
        return s.isEmpty ? emptyDefault : s
    }

    /// Build a marker URL under `labRoot` / `subdirectory` / `fileName`.
    public static func markerURL(
        labRoot: URL,
        subdirectory: String,
        fileName: String
    ) -> URL {
        labRoot
            .appendingPathComponent(subdirectory, isDirectory: true)
            .appendingPathComponent(fileName, isDirectory: false)
    }

    /// Encode a comma-separated list into a JSON string-array body fragment
    /// (e.g. `OPEN,EXEC` → `"OPEN","EXEC"` for embedding in `[\(…)]`).
    public static func jsonStringList(fromCSV csv: String) -> String {
        csv
            .split(separator: ",")
            .map { "\"\($0.trimmingCharacters(in: .whitespaces))\"" }
            .joined(separator: ",")
    }
}
