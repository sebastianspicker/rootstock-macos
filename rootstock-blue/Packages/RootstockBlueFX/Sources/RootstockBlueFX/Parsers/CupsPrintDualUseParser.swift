import Foundation
import RootstockBlueCore

/// CUPS / printer dual-use residual surface markers (Wave-13 red↔blue pair).
/// Honesty: never submits print jobs or reconfigures CUPS remotely.
public struct CupsPrintDualUseParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "CUPSPRINTDUAL", tier: .tier2,
        description: "CUPS printer dual-use surface markers"
    )
    public init() {}
    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()
        for rel in [
            "Library/Preferences/cups_print_dualuse.json",
            "Library/Logs/cups_print_dualuse.jsonl",
        ] {
            if let url = root.firstExisting([rel]), seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }
        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "cups_print_dualuse.json" || name == "cups_print_dualuse.jsonl"
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
        for k in ["password", "cookie", "secret", "token"] { _ = item[k] }
        let path = stringish(item["path"]) ?? stringish(item["tool_path"]) ?? ""
        let name = stringish(item["name"]) ?? stringish(item["kind"]) ?? stringish(item["label"]) ?? ""
        guard !path.isEmpty || !name.isEmpty else { return nil }
        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.lowercased().contains("password_dump") }
        }
        if !risk.contains("print_surface") { risk.append("print_surface") }
        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "cups.path": path, "cups.name": name,
            "cups.notes": stringish(item["notes"]) ?? "CUPS printer dual-use markers - never submits print jobs or reconfigures CUPS remotely",
            "cups.secrets_exported": "false",
            FieldTaxonomy.eventType: "cups.print", FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty { fields["cups.risk_tags"] = risk.joined(separator: ",") }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "cups.print",
                label: "CUPSPRINTDUAL"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "cups|\(name.isEmpty ? path : name)")],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.88
            )
        )
    }
}
