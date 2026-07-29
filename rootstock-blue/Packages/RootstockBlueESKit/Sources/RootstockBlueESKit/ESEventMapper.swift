import Foundation
import RootstockBlueCore

/// Maps raw ES-like dictionaries into EventEnvelope (stub for real ES types).
public enum ESEventMapper {
    public static func map(raw: [String: String], counters: inout LossCounters) -> EventEnvelope? {
        counters.recordReceived()
        guard let eventType = raw["event_type"] ?? raw[FieldTaxonomy.eventType] else {
            counters.recordMapFailure()
            return nil
        }
        var fields = raw
        fields[FieldTaxonomy.eventType] = eventType
        var entities: [EntityID] = []
        if let path = raw[FieldTaxonomy.processPath] ?? raw["process_path"] {
            let pid = Int32(raw[FieldTaxonomy.processPid] ?? raw["pid"] ?? "0") ?? 0
            entities.append(.process(pid: pid, path: path))
            fields[FieldTaxonomy.processPath] = path
        }
        if let file = raw[FieldTaxonomy.filePath] ?? raw["file_path"] {
            entities.append(.file(path: file))
            fields[FieldTaxonomy.filePath] = file
        }
        counters.recordMapped()
        return EventEnvelope(
            identity: .init(kind: eventType, label: "eskit"),
            capture: .init(source: .es),
            payload: .init(entityRefs: entities, properties: fields)
        )
    }
}
