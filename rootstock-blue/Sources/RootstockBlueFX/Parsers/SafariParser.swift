import Foundation
import RootstockBlueCore

/// Safari History.db + Downloads.plist → normalized timeline events (entity-linked).
public struct SafariParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SAFARI",
        tier: .tier2,
        description: "Safari history visits and downloads"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []

        for db in root.enumerate(matching: {
            $0.lastPathComponent == "History.db" && $0.path.contains("Safari")
        }) {
            events.append(contentsOf: try parseHistoryDB(db))
        }

        for plist in root.enumerate(matching: {
            $0.lastPathComponent == "Downloads.plist" && $0.path.contains("Safari")
        }) {
            events.append(contentsOf: parseDownloadsPlist(plist))
        }

        return events
    }

    private func parseHistoryDB(_ url: URL) throws -> [EventEnvelope] {
        let reader = try SQLiteReader(url: url)
        guard try reader.tableExists("history_visits"),
              try reader.tableExists("history_items")
        else { return [] }

        let rows = try reader.query(
            """
            SELECT
              v.id AS visit_id,
              CAST(v.visit_time AS TEXT) AS visit_time,
              COALESCE(v.title, '') AS title,
              COALESCE(i.url, '') AS url,
              COALESCE(i.domain_expansion, '') AS domain,
              COALESCE(CAST(i.visit_count AS TEXT), '') AS visit_count
            FROM history_visits v
            LEFT JOIN history_items i ON v.history_item = i.id;
            """
        )

        return rows.map { row in
            let urlString = row["url"] ?? ""
            let title = row["title"] ?? ""
            let when = Epochs.dateFromMacAbsolute(row["visit_time"] ?? "")
            return EventEnvelope(
                identity: EventEnvelope.Identity(
                    kind: "browser.visit",
                    label: "SAFARI"
                ),
                capture: EventEnvelope.Capture(
                    source: .parser,
                    eventTime: when,
                    collectedAt: Date()
                ),
                payload: EventEnvelope.Payload(
                    entityRefs: urlString.isEmpty ? [] : [EntityID(kind: .file, value: urlString)],
                    properties: [
                    "browser.engine": "safari",
                    "browser.url": urlString,
                    "browser.title": title,
                    "browser.domain": row["domain"] ?? "",
                    "browser.visit_count": row["visit_count"] ?? "",
                    "browser.visit_id": row["visit_id"] ?? "",
                    FieldTaxonomy.eventType: "browser.visit",
                    FieldTaxonomy.userName: inferUser(from: url) ?? "",
                ],
                    provenance: ArtifactRoot.pathKey(url),
                    confidence: 0.95
                )
            )
        }
    }

    private func parseDownloadsPlist(_ url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url), let entries = downloadEntries(from: data) else { return [] }
        return entries.compactMap { downloadEvent(from: $0, sourceURL: url) }
    }

    private func downloadEntries(from data: Data) -> [[String: Any]]? {
        if let dict = ArtifactIO.plistDict(from: data) { return dict["DownloadHistory"] as? [[String: Any]] }
        return ArtifactIO.plistArray(from: data)
    }

    private func downloadEvent(from entry: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let remote = stringValue(entry["DownloadEntryURL"]) ?? stringValue(entry["URL"]) ?? ""
        let path = stringValue(entry["DownloadEntryPath"]) ?? stringValue(entry["DownloadEntryPathRaw"]) ?? ""
        guard !remote.isEmpty || !path.isEmpty else { return nil }
        return EventEnvelope(identity: EventEnvelope.Identity(kind: "browser.download", label: "SAFARI"), capture: EventEnvelope.Capture(source: .parser, eventTime: Date(timeIntervalSince1970: 0), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: downloadReferences(path: path, remote: remote), properties: downloadFields(path: path, remote: remote, sourceURL: sourceURL), provenance: ArtifactRoot.pathKey(sourceURL), confidence: 0.9))
    }

    private func downloadReferences(path: String, remote: String) -> [EntityID] {
        var refs: [EntityID] = []
        if !path.isEmpty { refs.append(.file(path: path)) }
        if !remote.isEmpty { refs.append(EntityID(kind: .file, value: remote)) }
        return refs
    }

    private func downloadFields(path: String, remote: String, sourceURL: URL) -> [String: String] {
        ["browser.engine": "safari", "browser.download_url": remote, "browser.download_path": path, FieldTaxonomy.filePath: path, FieldTaxonomy.eventType: "browser.download", FieldTaxonomy.userName: inferUser(from: sourceURL) ?? ""]
    }
}
