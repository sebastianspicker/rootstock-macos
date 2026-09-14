import Foundation
import RootstockBlueCore

enum CasePackageVerification {
    static func canonicalEvidenceFiles(
        rootURL: URL,
        sha256sumsURL: URL,
        writeLockURL: URL,
        writeJournalURL: URL
    ) throws -> [URL] {
        let fm = FileManager.default
        try CaseFilesystem.requireDirectory(at: rootURL, label: "case root")
        try CaseFilesystem.requireRegularFile(at: sha256sumsURL, label: "sha256sums.txt")
        var enumerationFailure: Error?
        guard let enumerator = fm.enumerator(
            at: rootURL,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: [],
            errorHandler: { _, error in
                enumerationFailure = error
                return false
            }
        ) else {
            throw RootstockBlueError.invalidCasePackage("cannot enumerate package files")
        }
        let files = try collectEvidenceFiles(
            from: enumerator,
            rootURL: rootURL,
            sha256sumsURL: sha256sumsURL,
            writeLockURL: writeLockURL,
            writeJournalURL: writeJournalURL,
            enumerationFailure: &enumerationFailure
        )
        guard enumerationFailure == nil else {
            throw RootstockBlueError.invalidCasePackage("cannot completely enumerate package files")
        }
        return files.sorted { relativePath(for: $0, rootURL: rootURL) < relativePath(for: $1, rootURL: rootURL) }
    }

    private static func collectEvidenceFiles(
        from enumerator: FileManager.DirectoryEnumerator,
        rootURL: URL,
        sha256sumsURL: URL,
        writeLockURL: URL,
        writeJournalURL: URL,
        enumerationFailure: inout Error?
    ) throws -> [URL] {
        var files: [URL] = []
        for case let url as URL in enumerator {
            try collectEvidenceFile(
                url,
                rootURL: rootURL,
                sha256sumsURL: sha256sumsURL,
                writeLockURL: writeLockURL,
                writeJournalURL: writeJournalURL,
                enumerator: enumerator,
                files: &files
            )
        }
        return files
    }

    private static func collectEvidenceFile(
        _ url: URL,
        rootURL: URL,
        sha256sumsURL: URL,
        writeLockURL: URL,
        writeJournalURL: URL,
        enumerator: FileManager.DirectoryEnumerator,
        files: inout [URL]
    ) throws {
        let relative = relativePath(for: url, rootURL: rootURL)
        let type = try CaseFilesystem.nodeType(at: url, label: relative)
        try rejectUnsupportedEvidenceNode(type, relative: relative)
        if relative == sha256sumsURL.lastPathComponent {
            try requireChecksumManifest(type)
        } else if relative == writeLockURL.lastPathComponent {
            try requireWriteJournal(type, at: writeJournalURL)
            enumerator.skipDescendants()
        } else if type == .regularFile {
            files.append(url)
        }
    }

    private static func rejectUnsupportedEvidenceNode(_ type: CaseFilesystem.NodeType, relative: String) throws {
        if type == .symbolicLink {
            throw RootstockBlueError.invalidCasePackage("symbolic links are not supported: \(relative)")
        }
        if type == .other {
            throw RootstockBlueError.invalidCasePackage("unsupported filesystem entry: \(relative)")
        }
    }

    private static func requireChecksumManifest(_ type: CaseFilesystem.NodeType) throws {
        guard type == .regularFile else {
            throw RootstockBlueError.invalidCasePackage("sha256sums.txt must be a real regular file")
        }
    }

    private static func requireWriteJournal(_ type: CaseFilesystem.NodeType, at url: URL) throws {
        guard type == .directory else {
            throw RootstockBlueError.invalidCasePackage("write journal must be a real directory")
        }
        try CaseFilesystem.requireRegularFile(at: url, label: "write journal")
    }

    static func parseChecksumManifest(sha256sumsURL: URL) throws -> [String: String] {
        let content = try String(contentsOf: sha256sumsURL, encoding: .utf8)
        var lines = content.split(separator: "\n", omittingEmptySubsequences: false)
        if lines.last?.isEmpty == true { lines.removeLast() }
        guard !lines.isEmpty else {
            throw RootstockBlueError.invalidCasePackage("empty checksum manifest")
        }
        var entries: [String: String] = [:]
        for line in lines {
            let string = String(line)
            guard string.count > 66 else {
                throw RootstockBlueError.invalidCasePackage("malformed checksum manifest line")
            }
            let hash = String(string.prefix(64))
            let separatorStart = string.index(string.startIndex, offsetBy: 64)
            let separatorEnd = string.index(separatorStart, offsetBy: 2)
            guard string[separatorStart..<separatorEnd] == "  ",
                  hash.allSatisfy({ $0.isASCII && ($0.isNumber || ("a"..."f").contains($0)) })
            else {
                throw RootstockBlueError.invalidCasePackage("malformed checksum manifest line")
            }
            let path = String(string[separatorEnd...])
            guard isSafeRelativePath(path), path != sha256sumsURL.lastPathComponent,
                  entries[path] == nil
            else {
                throw RootstockBlueError.invalidCasePackage("invalid checksum manifest path")
            }
            entries[path] = hash
        }
        return entries
    }

    static func relativePath(for url: URL, rootURL: URL) -> String {
        let root = rootURL.standardizedFileURL.path + "/"
        let path = url.standardizedFileURL.path
        return String(path.dropFirst(root.count))
    }

    static func loadManifest(at url: URL) throws -> CaseManifest {
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(CaseManifest.self, from: data)
    }

    static func validateSupportedFormat(_ manifest: CaseManifest) throws {
        guard manifest.formatVersion == RootstockBlueVersion.casePackageFormat else {
            throw RootstockBlueError.invalidCasePackage(
                "unsupported case package format version \(manifest.formatVersion); expected \(RootstockBlueVersion.casePackageFormat)"
            )
        }
    }

    static func isSafeRelativePath(_ path: String) -> Bool {
        !path.isEmpty && !path.hasPrefix("/") && path.split(separator: "/", omittingEmptySubsequences: false).allSatisfy {
            !$0.isEmpty && $0 != "." && $0 != ".."
        }
    }
}
