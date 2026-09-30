import Foundation

/// Locates forensic artifacts under a rooted macOS-like tree (live mount or image extract).
public struct ArtifactRoot: Sendable {
    public let root: URL

    public init(source: ImageSource) {
        self.root = source.url.standardizedFileURL
    }

    public init(root: URL) {
        self.root = root.standardizedFileURL
    }

    public func file(_ relative: String) -> URL {
        root.appendingPathComponent(relative).standardizedFileURL
    }

    public func exists(_ relative: String) -> Bool {
        FileManager.default.fileExists(atPath: file(relative).path)
    }

    /// Search common absolute-style paths relative to the artifact root.
    public func firstExisting(_ relatives: [String]) -> URL? {
        for rel in relatives {
            let url = file(rel)
            if FileManager.default.fileExists(atPath: url.path) {
                return url
            }
        }
        return nil
    }

    /// Stable path key for de-duplicating URLs that may differ only by relative vs absolute form.
    public static func pathKey(_ url: URL) -> String {
        url.standardizedFileURL.resolvingSymlinksInPath().path
    }

    /// Enumerate files under root. Hidden entries (e.g. `.zsh_history`, `.fseventsd`) are included,
    /// forensic trees rely on them.
    public func enumerate(matching predicate: (URL) -> Bool) -> [URL] {
        var results: [URL] = []
        // Do NOT skip hidden files: .fseventsd, .zsh_history, .bash_history, etc.
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey],
            options: []
        ) else { return [] }
        for case let url as URL in enumerator {
            let standardized = url.standardizedFileURL
            if predicate(standardized) {
                results.append(standardized)
            }
        }
        return results
    }

    /// Append unique URLs using standardized path keys.
    public static func appendUnique(_ urls: inout [URL], _ candidate: URL) {
        let key = pathKey(candidate)
        if !urls.contains(where: { pathKey($0) == key }) {
            urls.append(candidate.standardizedFileURL)
        }
    }
}
