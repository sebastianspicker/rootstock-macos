import Foundation
import RootstockBlueCore

/// ScreenCapture / screenshot privacy dual-use depth markers (Wave-13 red↔blue pair).
/// Honesty: never captures screens or dumps Screen Recording TCC rows.
public struct ScreenCapturePrivacyDualUseParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SCREENCAPTUREPRIV", tier: .tier2,
        description: "ScreenCapture privacy dual-use surface markers"
    )
    public init() {}
    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()
        for rel in [
            "Library/Preferences/screencapture_privacy_dualuse.json",
            "Library/Logs/screencapture_privacy_dualuse.jsonl",
        ] {
            if let url = root.firstExisting([rel]), seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }
        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "screencapture_privacy_dualuse.json" || name == "screencapture_privacy_dualuse.jsonl"
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
        if !risk.contains("capture_surface") { risk.append("capture_surface") }
        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "scpriv.path": path, "scpriv.name": name,
            "scpriv.notes": stringish(item["notes"]) ?? "ScreenCapture privacy dual-use markers - never captures screens or dumps Screen Recording TCC rows",
            "scpriv.secrets_exported": "false",
            FieldTaxonomy.eventType: "screencapture.privacy", FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty { fields["scpriv.risk_tags"] = risk.joined(separator: ",") }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "screencapture.privacy",
                label: "SCREENCAPTUREPRIV"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "scpriv|\(name.isEmpty ? path : name)")],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.88
            )
        )
    }
}
