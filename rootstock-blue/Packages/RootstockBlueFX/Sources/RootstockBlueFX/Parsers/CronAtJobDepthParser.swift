import Foundation
import RootstockBlueCore

/// Cron / at job dual-use residual depth markers (Wave-14 red↔blue pair).
/// Honesty: never installs cron or at jobs outside the lab root.
public struct CronAtJobDepthParser: ArtifactParser {
    public let manifest = PluginManifest(id: "CRONATJOB", tier: .tier2, description: "Cron/at job depth markers")
    public init() {}
    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()
        for rel in ["Library/Preferences/cron_at_job_depth.json", "Library/Logs/cron_at_job_depth.jsonl"] {
            if let url = root.firstExisting([rel]), seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }
        for url in root.enumerate(matching: { url in
            let n = url.lastPathComponent
            return n == "cron_at_job_depth.json" || n == "cron_at_job_depth.jsonl"
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
        for k in ["password", "cookie", "secret", "token", "note_body"] { _ = item[k] }
        let path = stringish(item["path"]) ?? stringish(item["tool_path"]) ?? ""
        let name = stringish(item["name"]) ?? stringish(item["kind"]) ?? stringish(item["label"]) ?? ""
        guard !path.isEmpty || !name.isEmpty else { return nil }
        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.lowercased().contains("password_dump") }
        }
        if !risk.contains("cron_at_surface") { risk.append("cron_at_surface") }
        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "cronat.path": path, "cronat.name": name,
            "cronat.notes": stringish(item["notes"]) ?? "Cron/at job depth markers - never installs cron or at jobs outside the lab root",
            "cronat.secrets_exported": "false",
            FieldTaxonomy.eventType: "cron.at_job", FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty { fields["cronat.risk_tags"] = risk.joined(separator: ",") }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "cron.at_job",
                label: "CRONATJOB"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "cronat|\(name.isEmpty ? path : name)")],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.88
            )
        )
    }
}
