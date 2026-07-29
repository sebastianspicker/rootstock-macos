import Foundation
import RootstockCore

/// Offline project directory writer.
public struct ProjectBundle: Sendable {
    public var directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    public func prepare() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    public func write(
        findings: [Finding],
        state: CollectedState,
        meta: [String: String] = [:]
    ) throws {
        try prepare()
        let findingsURL = directory.appendingPathComponent("findings.jsonl")
        try JSONLReporter.render(findings).write(to: findingsURL, options: .atomic)

        let stateURL = directory.appendingPathComponent("state.json")
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(state).write(to: stateURL, options: .atomic)

        var fullMeta = meta
        fullMeta["schemaVersion"] = RootstockCore.schemaVersion
        fullMeta["rootstockRedVersion"] = RootstockCore.version
        fullMeta["findingCount"] = String(findings.count)
        let metaURL = directory.appendingPathComponent("meta.json")
        try JSONSerialization.data(
            withJSONObject: fullMeta,
            options: [.prettyPrinted, .sortedKeys]
        ).write(to: metaURL, options: .atomic)

        let mdURL = directory.appendingPathComponent("report.md")
        try MarkdownReporter.render(findings, state: state)
            .data(using: .utf8)?
            .write(to: mdURL, options: .atomic)
    }
}
