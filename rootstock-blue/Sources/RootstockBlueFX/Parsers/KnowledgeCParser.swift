import Foundation
import RootstockBlueCore

/// Synthetic / simplified knowledgeC app-usage streams → pattern-of-life events.
/// Emits entity-linked timeline rows.
public struct KnowledgeCParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "KNOWLEDGEC",
        tier: .tier2,
        description: "knowledgeC-style app usage / portrait streams (version-tolerant)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var dbs = root.enumerate(matching: {
            $0.lastPathComponent == "knowledgeC.db"
                || ($0.pathExtension == "db" && $0.path.contains("Knowledge"))
        })
        // Prefer unique paths
        var unique: [URL] = []
        for db in dbs { ArtifactRoot.appendUnique(&unique, db) }
        dbs = unique

        var events: [EventEnvelope] = []
        for db in dbs {
            events.append(contentsOf: try parseDB(db))
        }
        return events
    }

    private func parseDB(_ url: URL) throws -> [EventEnvelope] {
        let reader = try SQLiteReader(url: url)
        // Prefer simplified fixture table; also tolerate ZOBJECT-like names if present.
        if try reader.tableExists("objects") {
            let rows = try reader.query(
                """
                SELECT
                  CAST(id AS TEXT) AS id,
                  COALESCE(stream, '') AS stream,
                  COALESCE(CAST(start_date AS TEXT), '') AS start_date,
                  COALESCE(CAST(end_date AS TEXT), '') AS end_date,
                  COALESCE(value_string, '') AS value_string
                FROM objects;
                """
            )
            return rows.map { mapObjectRow($0, dbPath: url) }
        }

        if try reader.tableExists("ZOBJECT") {
            // Best-effort classic knowledgeC - streams often in ZSTREAM_NAME via join; keep simple.
            let rows = try reader.query(
                """
                SELECT
                  CAST(Z_PK AS TEXT) AS id,
                  COALESCE(CAST(ZSTARTDATE AS TEXT), '') AS start_date,
                  COALESCE(CAST(ZENDDATE AS TEXT), '') AS end_date,
                  COALESCE(ZVALUESTRING, '') AS value_string,
                  COALESCE(CAST(ZSTREAMNAME AS TEXT), '/unknown') AS stream
                FROM ZOBJECT
                LIMIT 5000;
                """
            )
            return rows.map { mapObjectRow($0, dbPath: url) }
        }

        return []
    }

    private func mapObjectRow(_ row: [String: String], dbPath: URL) -> EventEnvelope {
        let stream = row["stream"] ?? ""
        let value = row["value_string"] ?? ""
        let start = Epochs.dateFromMacAbsolute(row["start_date"] ?? "")
        let end = Epochs.dateFromMacAbsolute(row["end_date"] ?? "")
        let duration = max(0, end.timeIntervalSince(start))

        var eventType = "pol.object"
        if stream.contains("app/usage") || stream.contains("appUsage") {
            eventType = "pol.app_usage"
        } else if stream.contains("portrait") {
            eventType = "pol.portrait"
        }

        var refs: [EntityID] = []
        if !value.isEmpty {
            refs.append(EntityID(kind: .persistence, value: "bundle|\(value)"))
        }

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: eventType,
                label: "KNOWLEDGEC"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: start,
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: refs,
                properties: [
                "pol.stream": stream,
                "pol.value": value,
                "pol.duration_seconds": String(Int(duration)),
                "pol.object_id": row["id"] ?? "",
                FieldTaxonomy.eventType: eventType,
                FieldTaxonomy.userName: inferUser(from: dbPath) ?? "",
            ],
                provenance: ArtifactRoot.pathKey(dbPath),
                confidence: 0.85
            )
        )
    }

}
