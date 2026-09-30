import Foundation
import RootstockBlueCore

/// Chromium History (urls/visits/downloads) → entity-linked timeline events.
public struct ChromiumParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "CHROMIUM",
        tier: .tier2,
        description: "Chrome/Edge/Chromium history visits and downloads"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        // Chromium profiles store a file named "History" (no extension)
        let histories = root.enumerate(matching: { url in
            url.lastPathComponent == "History"
                && (url.path.contains("Chrome")
                    || url.path.contains("Chromium")
                    || url.path.contains("Edge")
                    || url.path.contains("Brave")
                    || url.path.contains("Google"))
        })
        for db in histories {
            events.append(contentsOf: try parseHistory(db))
        }
        return events
    }

    private func parseHistory(_ url: URL) throws -> [EventEnvelope] {
        let reader = try SQLiteReader(url: url)
        let engine = browserEngine(from: url.path)
        var events: [EventEnvelope] = []
        if try reader.tableExists("visits"), try reader.tableExists("urls") {
            events.append(contentsOf: try visitEvents(reader: reader, url: url, engine: engine))
        }
        if try reader.tableExists("downloads") {
            events.append(contentsOf: try downloadEvents(reader: reader, url: url, engine: engine))
        }
        return events
    }

    private func visitEvents(reader: SQLiteReader, url: URL, engine: String) throws -> [EventEnvelope] {
        let rows = try reader.query("""
            SELECT CAST(v.id AS TEXT) AS visit_id, CAST(v.visit_time AS TEXT) AS visit_time,
              COALESCE(u.url, '') AS url, COALESCE(u.title, '') AS title,
              COALESCE(CAST(u.visit_count AS TEXT), '') AS visit_count
            FROM visits v LEFT JOIN urls u ON v.url = u.id;
            """)
        return rows.map { visitEvent(row: $0, sourceURL: url, engine: engine) }
    }

    private func visitEvent(row: [String: String], sourceURL: URL, engine: String) -> EventEnvelope {
        let urlString = row["url"] ?? ""
        let properties = ["browser.engine": engine, "browser.url": urlString, "browser.title": row["title"] ?? "", "browser.visit_count": row["visit_count"] ?? "", "browser.visit_id": row["visit_id"] ?? "", FieldTaxonomy.eventType: "browser.visit", FieldTaxonomy.userName: inferUser(from: sourceURL) ?? ""]
        return EventEnvelope(identity: EventEnvelope.Identity(kind: "browser.visit", label: "CHROMIUM"), capture: EventEnvelope.Capture(source: .parser, eventTime: Epochs.dateFromChromeMicroseconds(row["visit_time"] ?? ""), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: urlString.isEmpty ? [] : [EntityID(kind: .file, value: urlString)], properties: properties, provenance: ArtifactRoot.pathKey(sourceURL), confidence: 0.95))
    }

    private func downloadEvents(reader: SQLiteReader, url: URL, engine: String) throws -> [EventEnvelope] {
        let rows = try reader.query("""
            SELECT CAST(id AS TEXT) AS id, COALESCE(target_path, current_path, '') AS path,
              COALESCE(tab_url, site_url, referrer, '') AS source_url,
              COALESCE(CAST(start_time AS TEXT), '') AS start_time, COALESCE(mime_type, '') AS mime_type,
              COALESCE(CAST(received_bytes AS TEXT), '') AS received_bytes FROM downloads;
            """)
        return rows.map { downloadEvent(row: $0, sourceURL: url, engine: engine) }
    }

    private func downloadEvent(row: [String: String], sourceURL: URL, engine: String) -> EventEnvelope {
        let path = row["path"] ?? ""
        let downloadURL = row["source_url"] ?? ""
        let fields = ["browser.engine": engine, "browser.download_path": path, "browser.download_url": downloadURL, "browser.mime_type": row["mime_type"] ?? "", "browser.received_bytes": row["received_bytes"] ?? "", FieldTaxonomy.filePath: path, FieldTaxonomy.eventType: "browser.download", FieldTaxonomy.userName: inferUser(from: sourceURL) ?? ""]
        return EventEnvelope(identity: EventEnvelope.Identity(kind: "browser.download", label: "CHROMIUM"), capture: EventEnvelope.Capture(source: .parser, eventTime: Epochs.dateFromChromeMicroseconds(row["start_time"] ?? ""), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: downloadReferences(path: path, sourceURL: downloadURL), properties: fields, provenance: ArtifactRoot.pathKey(sourceURL), confidence: 0.92))
    }

    private func downloadReferences(path: String, sourceURL: String) -> [EntityID] {
        var references: [EntityID] = []
        if !path.isEmpty { references.append(.file(path: path)) }
        if !sourceURL.isEmpty { references.append(EntityID(kind: .file, value: sourceURL)) }
        return references
    }

    private func browserEngine(from path: String) -> String {
        if path.contains("Edge") { return "edge" }
        if path.contains("Brave") { return "brave" }
        if path.contains("Chromium") { return "chromium" }
        return "chrome"
    }

}
