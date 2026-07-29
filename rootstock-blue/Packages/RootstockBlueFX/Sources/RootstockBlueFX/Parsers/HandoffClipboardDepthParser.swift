import Foundation
import RootstockBlueCore

/// Handoff / Universal Clipboard residual depth markers (Wave-16 red↔blue pair).
/// Honesty: never reads Universal Clipboard contents or forges Handoff activity.
public struct HandoffClipboardDepthParser: ArtifactParser {
    public let manifest = PluginManifest(id: "HANDOFFCB", tier: .tier2, description: "Handoff clipboard depth markers")
    public init() {}
    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()
        for rel in ["Library/Preferences/handoff_clipboard_depth.json", "Library/Logs/handoff_clipboard_depth.jsonl"] {
            if let url = root.firstExisting([rel]), seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }
        for url in root.enumerate(matching: { url in
            let n = url.lastPathComponent
            return n == "handoff_clipboard_depth.json" || n == "handoff_clipboard_depth.jsonl"
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
        if !risk.contains("handoff_surface") { risk.append("handoff_surface") }
        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "hdoffcb.path": path, "hdoffcb.name": name,
            "hdoffcb.notes": stringish(item["notes"]) ?? "Handoff clipboard depth markers - never reads Universal Clipboard contents or forges Handoff activity",
            "hdoffcb.secrets_exported": "false",
            FieldTaxonomy.eventType: "handoff.clipboard", FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty { fields["hdoffcb.risk_tags"] = risk.joined(separator: ",") }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "handoff.clipboard",
                label: "HANDOFFCB"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "hdoffcb|\(name.isEmpty ? path : name)")],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.88
            )
        )
    }
}
