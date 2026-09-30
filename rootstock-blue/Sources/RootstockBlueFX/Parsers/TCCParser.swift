/// Offline forensic parser: TCCParser - fixture-backed IR events (no secret export).
import Foundation
import RootstockBlueCore
import RootstockMacFacts

public struct TCCParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "TCC",
        tier: .tier1,
        description: "Parse TCC.db privacy permissions"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var dbURLs: [URL] = []

        if let u = root.firstExisting([
            MacSecurityPaths.userTCCDatabaseRelative,
            "private/var/db/TCC/TCC.db",
        ]) {
            ArtifactRoot.appendUnique(&dbURLs, u)
        }

        for url in root.enumerate(matching: { $0.lastPathComponent == "TCC.db" }) {
            ArtifactRoot.appendUnique(&dbURLs, url)
        }

        var events: [EventEnvelope] = []
        for dbURL in dbURLs {
            events.append(contentsOf: try parseDatabase(at: dbURL))
        }
        return events
    }

    private func parseDatabase(at url: URL) throws -> [EventEnvelope] {
        let reader = try SQLiteReader(url: url)
        guard try reader.tableExists("access") else { return [] }

        let rows = try reader.query(
            """
            SELECT service, client,
                   CAST(auth_value AS TEXT) AS auth_value,
                   CAST(last_modified AS TEXT) AS last_modified
            FROM access;
            """
        )

        let authNames: [String: String] = [
            "0": "denied", "1": "unknown", "2": "allowed", "3": "limited",
        ]

        return rows.map { row in
            let service = row["service"] ?? ""
            let client = row["client"] ?? ""
            let auth = row["auth_value"] ?? ""
            let authLabel = authNames[auth] ?? auth
            let modified = Epochs.dateFromMacAbsolute(row["last_modified"] ?? "")

            return EventEnvelope(
                identity: EventEnvelope.Identity(
                    kind: "tcc.access",
                    label: "TCC"
                ),
                capture: EventEnvelope.Capture(
                    source: .parser,
                    eventTime: modified,
                    collectedAt: Date()
                ),
                payload: EventEnvelope.Payload(
                    entityRefs: [
                    EntityID(kind: .tcc, value: "\(service)|\(client)"),
                ],
                    properties: [
                    FieldTaxonomy.tccService: service,
                    "tcc.service_display": TCCServiceCatalog.displayName(for: service),
                    FieldTaxonomy.tccIdentity: client,
                    FieldTaxonomy.tccRight: authLabel,
                    "tcc.auth_value": auth,
                    "tcc.db_path": ArtifactRoot.pathKey(url),
                    FieldTaxonomy.eventType: "tcc.access",
                ],
                    provenance: ArtifactRoot.pathKey(url),
                    confidence: 0.95
                )
            )
        }
    }
}
