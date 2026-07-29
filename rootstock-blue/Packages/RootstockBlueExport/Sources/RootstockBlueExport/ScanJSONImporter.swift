import Foundation
import RootstockBlueCase
import RootstockBlueCore
import RootstockMacFacts

/// Import a core Rootstock collector `scan.json` into a blue case as timeline events.
///
/// Family bridge (DD-011): optional, fail-closed on missing required meta.
/// Provenance: `sourcePlugin` values use `collector.*` prefix.
public enum ScanJSONImporter: Sendable {
    private struct ScanContext {
        let id: String
        let host: String
        let capturedAt: Date
    }

    public struct Summary: Sendable, Equatable {
        public var tccEvents: Int
        public var launchItemEvents: Int
        public var metaNotes: Int

        public var totalEvents: Int { tccEvents + launchItemEvents + metaNotes }
    }

    /// Parse collector scan JSON data into `EventEnvelope`s (does not write the case).
    public static func events(from data: Data) throws -> (events: [EventEnvelope], summary: Summary) {
        let root = try scanRoot(from: data)
        let context = scanContext(root)
        var events = [metadataEvent(root: root, context: context)]
        let tccEvents = importedTCCEvents(root: root, context: context)
        let launchEvents = importedLaunchEvents(root: root, context: context)
        events.append(contentsOf: tccEvents)
        events.append(contentsOf: launchEvents)
        return (events, Summary(tccEvents: tccEvents.count, launchItemEvents: launchEvents.count, metaNotes: 1))
    }

    private static func scanRoot(from data: Data) throws -> [String: Any] {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw RootstockBlueError.io("scan.json root must be an object")
        }
        guard let scanID = root["scan_id"] as? String, !scanID.isEmpty else {
            throw RootstockBlueError.io("scan.json missing scan_id")
        }
        return root
    }

    private static func scanContext(_ root: [String: Any]) -> ScanContext {
        let id = root["scan_id"] as? String ?? ""
        let host = root["hostname"] as? String ?? ""
        return ScanContext(id: id, host: host, capturedAt: parseISO8601(root["timestamp"] as? String) ?? Date())
    }

    private static func metadataEvent(root: [String: Any], context: ScanContext) -> EventEnvelope {
        EventEnvelope(
            identity: .init(kind: "collector.scan_meta", label: "collector.meta"),
            capture: .init(source: .parser, eventTime: context.capturedAt),
            payload: .init(
                entityRefs: [.init(kind: .host, value: context.host.isEmpty ? context.id : context.host)],
                properties: [
                    "collector.scan_id": context.id,
                    "collector.hostname": context.host,
                    "collector.macos_version": root["macos_version"] as? String ?? "",
                    "collector.version": root["collector_version"] as? String ?? "",
                    "family.source": "collector",
                    FieldTaxonomy.eventType: "collector.scan_meta",
                ],
                provenance: "scan_id:\(context.id)"
            )
        )
    }

    private static func importedTCCEvents(root: [String: Any], context: ScanContext) -> [EventEnvelope] {
        guard let grants = root["tcc_grants"] as? [[String: Any]] else { return [] }
        return grants.map { grant in
            let service = grant["service"] as? String ?? ""
            let client = grant["client"] as? String ?? ""
            return EventEnvelope(
                identity: .init(kind: "tcc.grant", label: "collector.tcc"),
                capture: .init(source: .parser, eventTime: context.capturedAt),
                payload: .init(
                    entityRefs: [.init(kind: .tcc, value: "\(service)|\(client)")],
                    properties: tccProperties(grant, scanID: context.id, service: service, client: client),
                    provenance: "scan_id:\(context.id)",
                    confidence: 0.9
                )
            )
        }
    }

    private static func tccProperties(_ grant: [String: Any], scanID: String, service: String, client: String) -> [String: String] {
        [
            FieldTaxonomy.tccService: service,
            "tcc.service_display": TCCServiceCatalog.displayName(for: service),
            FieldTaxonomy.tccIdentity: client,
            "tcc.scope": grant["scope"] as? String ?? "",
            "tcc.auth_value": grant["auth_value"].map { "\($0)" } ?? "",
            "collector.scan_id": scanID,
            "family.source": "collector",
            FieldTaxonomy.eventType: "tcc.grant",
        ]
    }

    private static func importedLaunchEvents(root: [String: Any], context: ScanContext) -> [EventEnvelope] {
        guard let items = root["launch_items"] as? [[String: Any]] else { return [] }
        return items.map { item in
            let label = item["label"] as? String ?? ""
            let path = item["path"] as? String ?? ""
            return EventEnvelope(
                identity: .init(kind: "persistence.launch_item", label: "collector.persistence"),
                capture: .init(source: .parser, eventTime: context.capturedAt),
                payload: .init(
                    entityRefs: [.init(kind: .process, value: label.isEmpty ? path : label)],
                    properties: launchProperties(item, scanID: context.id, label: label, path: path),
                    provenance: path.isEmpty ? "scan_id:\(context.id)" : path,
                    confidence: 0.9
                )
            )
        }
    }

    private static func launchProperties(_ item: [String: Any], scanID: String, label: String, path: String) -> [String: String] {
        [
            "persist.label": label,
            "persist.path": path,
            "persist.program": item["program"] as? String ?? "",
            "persist.type": item["type"] as? String ?? "",
            "collector.scan_id": scanID,
            "family.source": "collector",
            FieldTaxonomy.eventType: "persistence.launch_item",
        ]
    }

    /// Load scan.json from disk and append events into the case package.
    @discardableResult
    public static func importIntoCase(scanURL: URL, casePackage: CasePackage) throws -> Summary {
        let data = try Data(contentsOf: scanURL)
        let (events, summary) = try events(from: data)
        for event in events {
            try casePackage.appendEventJSONL(event, stream: "es")
            try casePackage.insertTimelineEvent(event)
        }
        try casePackage.appendCustody(
            CustodyEvent(
                actor: "rootstock-blue",
                action: "import.scan_json",
                detail: "Imported \(summary.totalEvents) events from \(scanURL.lastPathComponent)"
            )
        )
        try casePackage.updateHashes()
        return summary
    }

    private static func parseISO8601(_ value: String?) -> Date? {
        guard let value, !value.isEmpty else { return nil }
        let frac = ISO8601DateFormatter()
        frac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = frac.date(from: value) { return d }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: value)
    }
}
