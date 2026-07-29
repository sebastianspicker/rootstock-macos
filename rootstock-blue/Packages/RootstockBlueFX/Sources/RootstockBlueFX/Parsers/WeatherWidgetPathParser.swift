import Foundation
import RootstockBlueCore

/// Weather / widget data residual plane markers (Wave-16 red↔blue pair).
/// Honesty: never dumps weather personalization data or widget timeline contents.
public struct WeatherWidgetPathParser: ArtifactParser {
    public let manifest = PluginManifest(id: "WTHRWDG", tier: .tier2, description: "Weather widget residual markers")
    public init() {}
    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()
        for rel in ["Library/Preferences/weather_widget_path.json", "Library/Logs/weather_widget_path.jsonl"] {
            if let url = root.firstExisting([rel]), seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }
        for url in root.enumerate(matching: { url in
            let n = url.lastPathComponent
            return n == "weather_widget_path.json" || n == "weather_widget_path.jsonl"
        }) where seen.insert(url) {
            events.append(contentsOf: parseFile(at: url))
        }
        return events
    }
    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return ArtifactIO.jsonlDictionaries(contentsOf: url).compactMap { makeEvent(from: $0, sourceURL: url) }
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url, nestedKeys: ["items", "entries", "surfaces", "paths"],
            identityKeys: ["path", "name", "label", "kind"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }
    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        for k in ["password", "cookie", "secret", "token", "private_key", "health_sample", "pass_data"] { _ = item[k] }
        let path = stringish(item["path"]) ?? stringish(item["tool_path"]) ?? ""
        let name = stringish(item["name"]) ?? stringish(item["kind"]) ?? stringish(item["label"]) ?? ""
        guard !path.isEmpty || !name.isEmpty else { return nil }
        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.lowercased().contains("password_dump") }
        }
        if !risk.contains("weather_surface") { risk.append("weather_surface") }
        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "wthrwdg.path": path, "wthrwdg.name": name,
            "wthrwdg.notes": stringish(item["notes"]) ?? "Weather widget residual markers - never dumps weather personalization data or widget timeline contents",
            "wthrwdg.secrets_exported": "false",
            FieldTaxonomy.eventType: "weather.widget", FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty { fields["wthrwdg.risk_tags"] = risk.joined(separator: ",") }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "weather.widget",
                label: "WTHRWDG"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "wthrwdg|\(name.isEmpty ? path : name)")],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.88
            )
        )
    }
}
