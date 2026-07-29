import Foundation
import RootstockBlueCore

/// Gatekeeper assessment / syspolicyd history depth markers (Wave-13 red↔blue pair).
/// Honesty: never clears Gatekeeper assessments or disables syspolicyd.
public struct GatekeeperAssessmentHistoryParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "GKASSESSMENTHIST", tier: .tier2,
        description: "Gatekeeper assessment history surface markers"
    )
    public init() {}
    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()
        for rel in [
            "Library/Preferences/gatekeeper_assessment_history.json",
            "Library/Logs/gatekeeper_assessment_history.jsonl",
        ] {
            if let url = root.firstExisting([rel]), seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }
        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "gatekeeper_assessment_history.json" || name == "gatekeeper_assessment_history.jsonl"
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
        if !risk.contains("assessment_surface") { risk.append("assessment_surface") }
        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "gkh.path": path, "gkh.name": name,
            "gkh.notes": stringish(item["notes"]) ?? "Gatekeeper assessment history markers - never clears Gatekeeper assessments or disables syspolicyd",
            "gkh.secrets_exported": "false",
            FieldTaxonomy.eventType: "gatekeeper.assessment", FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty { fields["gkh.risk_tags"] = risk.joined(separator: ",") }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "gatekeeper.assessment",
                label: "GKASSESSMENTHIST"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "gkh|\(name.isEmpty ? path : name)")],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.88
            )
        )
    }
}
