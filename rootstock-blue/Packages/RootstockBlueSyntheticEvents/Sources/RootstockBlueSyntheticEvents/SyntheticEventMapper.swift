import Foundation
import RootstockBlueCore

/// Maps synthetic fixture dictionaries into normalized event envelopes.
public enum SyntheticEventMapper {
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
            identity: .init(kind: eventType, label: "synthetic"),
            capture: .init(source: .synthetic),
            payload: .init(entityRefs: entities, properties: fields)
        )
    }
}
