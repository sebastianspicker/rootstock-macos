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
        eligibleNode(relative) != nil
    }

    /// Search common absolute-style paths relative to the artifact root.
    public func firstExisting(_ relatives: [String]) -> URL? {
        for rel in relatives {
            if let url = eligibleNode(rel) {
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
            if eligibleURL(standardized) && predicate(standardized) {
                results.append(standardized)
            }
        }
        return results
    }

    /// List immediate children without following a directory or child outside the evidence root.
    public func contentsOfDirectory(
        _ relative: String,
        options: FileManager.DirectoryEnumerationOptions = []
    ) -> [URL] {
        guard let directory = eligibleNode(relative, requireDirectory: true),
              let items = directoryContents(directory, options: options) else { return [] }
        return items
    }

    public func contentsOfDirectory(
        at directory: URL,
        options: FileManager.DirectoryEnumerationOptions = []
    ) -> [URL] {
        guard eligibleURL(directory),
              let values = try? directory.resourceValues(forKeys: [.isDirectoryKey]),
              values.isDirectory == true,
              let items = directoryContents(directory, options: options)
        else { return [] }
        return items
    }

    private func directoryContents(
        _ directory: URL,
        options: FileManager.DirectoryEnumerationOptions
    ) -> [URL]? {
        guard let items = try? FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey],
            options: options
        ) else { return nil }
        return items.map(\.standardizedFileURL).filter(eligibleURL)
    }

    private func eligibleNode(_ relative: String, requireDirectory: Bool = false) -> URL? {
        let candidate = file(relative)
        guard eligibleURL(candidate) else { return nil }
        if requireDirectory {
            let values = try? candidate.resourceValues(forKeys: [.isDirectoryKey])
            guard values?.isDirectory == true else { return nil }
        }
        return candidate
    }

    private func eligibleURL(_ candidate: URL) -> Bool {
        let lexicalRoot = root.standardizedFileURL.path
        let lexicalCandidate = candidate.standardizedFileURL.path
        guard Self.contains(lexicalCandidate, under: lexicalRoot),
              FileManager.default.fileExists(atPath: lexicalCandidate)
        else { return false }

        let canonicalRoot = root.resolvingSymlinksInPath().standardizedFileURL.path
        let canonicalCandidate = candidate.resolvingSymlinksInPath().standardizedFileURL.path
        let resolvedCandidate = candidate.resolvingSymlinksInPath().standardizedFileURL
        guard Self.contains(canonicalCandidate, under: canonicalRoot),
              let values = try? resolvedCandidate.resourceValues(
                  forKeys: [.isRegularFileKey, .isDirectoryKey]
              )
        else { return false }
        return values.isRegularFile == true || values.isDirectory == true
    }

    private static func contains(_ candidate: String, under root: String) -> Bool {
        candidate == root || candidate.hasPrefix(root.hasSuffix("/") ? root : root + "/")
    }

    /// Append unique URLs using standardized path keys.
    public static func appendUnique(_ urls: inout [URL], _ candidate: URL) {
        let key = pathKey(candidate)
        if !urls.contains(where: { pathKey($0) == key }) {
            urls.append(candidate.standardizedFileURL)
        }
    }
}
