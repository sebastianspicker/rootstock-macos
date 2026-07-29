import Foundation
import RootstockBlueCore

/// FaceTime / camera pipeline dual-use surface markers (Wave-16 red↔blue pair).
/// Honesty: never activates camera/mic or dumps FaceTime call history contents.
public struct FacetimeCameraSurfaceParser: ArtifactParser {
    public let manifest = PluginManifest(id: "FTCAM", tier: .tier2, description: "FaceTime camera dual-use markers")
    public init() {}
    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()
        for rel in ["Library/Preferences/facetime_camera_surface.json", "Library/Logs/facetime_camera_surface.jsonl"] {
            if let url = root.firstExisting([rel]), seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }
        for url in root.enumerate(matching: { url in
            let n = url.lastPathComponent
            return n == "facetime_camera_surface.json" || n == "facetime_camera_surface.jsonl"
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
        if !risk.contains("facetime_surface") { risk.append("facetime_surface") }
        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "ftcam.path": path, "ftcam.name": name,
            "ftcam.notes": stringish(item["notes"]) ?? "FaceTime camera dual-use markers - never activates camera/mic or dumps FaceTime call history contents",
            "ftcam.secrets_exported": "false",
            FieldTaxonomy.eventType: "facetime.camera", FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty { fields["ftcam.risk_tags"] = risk.joined(separator: ",") }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "facetime.camera",
                label: "FTCAM"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "ftcam|\(name.isEmpty ? path : name)")],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.88
            )
        )
    }
}
