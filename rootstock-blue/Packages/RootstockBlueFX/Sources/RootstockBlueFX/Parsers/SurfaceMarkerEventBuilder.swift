import Foundation
import RootstockBlueCore

struct SurfaceMarkerEventSpec {
    let fieldPrefix: String
    let eventType: String
    let identityKind: String
    let identityLabel: String
    let entityPrefix: String
    let defaultRiskTag: String
    let defaultNotes: String
}

private struct SurfaceMarkerRecord {
    let item: [String: Any]
    let sourceURL: URL
    let path: String
    let name: String
    let riskTags: [String]
}

enum SurfaceMarkerEventBuilder {
    static func makeEvent(
        from item: [String: Any],
        sourceURL: URL,
        spec: SurfaceMarkerEventSpec
    ) -> EventEnvelope? {
        discardSecrets(in: item)
        let path = firstString(in: item, keys: ["path", "tile_path", "handler_path", "tool_path"])
        let name = firstString(in: item, keys: ["name", "rule_name", "kind", "label"])
        guard !path.isEmpty || !name.isEmpty else { return nil }
        let record = SurfaceMarkerRecord(item: item, sourceURL: sourceURL, path: path, name: name, riskTags: riskTags(in: item, defaultTag: spec.defaultRiskTag))
        let fields = fields(for: record, spec: spec)
        return event(record: record, fields: fields, spec: spec)
    }

    private static func discardSecrets(in item: [String: Any]) {
        for key in ["password", "cookie", "cookie_value", "secret", "token", "keychain_data"] {
            _ = item[key]
        }
    }

    private static func firstString(in item: [String: Any], keys: [String]) -> String {
        for key in keys {
            if let value = stringish(item[key]) { return value }
        }
        return ""
    }

    private static func riskTags(in item: [String: Any], defaultTag: String) -> [String] {
        var tags = (stringish(item["risk_tags"]) ?? "").split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.lowercased().contains("password_dump") }
        if tags.isEmpty { tags.append(defaultTag) }
        if !tags.contains(defaultTag) { tags.append(defaultTag) }
        return tags
    }

    private static func fields(for record: SurfaceMarkerRecord, spec: SurfaceMarkerEventSpec) -> [String: String] {
        let prefix = spec.fieldPrefix
        let user = stringish(record.item["user"]) ?? inferUser(from: record.path) ?? inferUser(from: record.sourceURL.path) ?? ""
        var fields = [
            "\(prefix).path": record.path,
            "\(prefix).name": record.name,
            "\(prefix).notes": stringish(record.item["notes"]) ?? spec.defaultNotes,
            "\(prefix).secrets_exported": "false",
            FieldTaxonomy.eventType: spec.eventType,
            FieldTaxonomy.userName: user,
        ]
        addOptionalFields(from: record.item, to: &fields, prefix: prefix)
        fields["\(prefix).risk_tags"] = record.riskTags.joined(separator: ",")
        return fields
    }

    private static func addOptionalFields(from item: [String: Any], to fields: inout [String: String], prefix: String) {
        if let host = stringish(item["url_host"]) { fields["\(prefix).url_host"] = host }
        if let share = stringish(item["share_url"]) { fields["\(prefix).share_url"] = share }
        if let depth = stringish(item["depth"]) { fields["\(prefix).depth"] = depth }
        if boolish(item["runs_script"]) == true { fields["\(prefix).runs_script"] = "true" }
        if boolish(item["tool_present"]) == true { fields["\(prefix).tool_present"] = "true" }
    }

    private static func event(record: SurfaceMarkerRecord, fields: [String: String], spec: SurfaceMarkerEventSpec) -> EventEnvelope {
        EventEnvelope(
            identity: EventEnvelope.Identity(kind: spec.identityKind, label: spec.identityLabel),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(record.item["timestamp"] ?? record.item["seen_at"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "\(spec.entityPrefix)|\(record.name.isEmpty ? record.path : record.name)")],
                properties: fields,
                provenance: ArtifactRoot.pathKey(record.sourceURL),
                confidence: 0.88
            )
        )
    }
}
