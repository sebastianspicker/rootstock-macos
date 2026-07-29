import Foundation
import RootstockBlueCore

/// QuickLook thumbnail cache inventory - which files were previewed.
///
/// Sensitive paths in QL cache are high-ROI for IR (documents opened even if deleted).
public struct QuickLookParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "QUICKLOOK",
        tier: .tier2,
        description: "QuickLook thumbnail cache inventory (previewed paths)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/quicklook_cache.json",
            "Library/Preferences/quicklook_export.json",
            "Library/Logs/quicklook_cache.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "quicklook_cache.json"
                || name == "quicklook_export.json"
                || name == "quicklook_cache.jsonl"
        }) where seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
        }

        events.append(contentsOf: parseMarkers(root: root, seen: &seen))

        return events
    }

    private func parseMarkers(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: { url in
            url.path.contains("QuickLook") && (url.lastPathComponent.hasSuffix(".marker") || url.lastPathComponent == "index.sqlite" || url.lastPathComponent.hasSuffix(".sqlite.marker"))
        }) {
            let key = "ql-marker:" + ArtifactRoot.pathKey(url)
            if seen.insert(pathKey: key) {
                events.append(
                    EventEnvelope(
                        identity: EventEnvelope.Identity(
                            kind: "filesystem.quicklook",
                            label: "QUICKLOOK"
                        ),
                        capture: EventEnvelope.Capture(
                            source: .parser,
                            eventTime: Date(timeIntervalSince1970: 0),
                            collectedAt: Date()
                        ),
                        payload: EventEnvelope.Payload(
                            entityRefs: [.file(path: ArtifactRoot.pathKey(url))],
                            properties: [
                            "ql.cache_path": ArtifactRoot.pathKey(url),
                            "ql.marker": "true",
                            FieldTaxonomy.eventType: "filesystem.quicklook",
                        ],
                            provenance: ArtifactRoot.pathKey(url),
                            confidence: 0.7
                        )
                    )
                )
            }
        }
        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["thumbnails", "items", "cache"],
            identityKeys: ["path"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        guard let details = quickLookDetails(from: item) else { return nil }
        let fields = quickLookFields(item: item, details: details)
        return quickLookEnvelope(item: item, sourceURL: sourceURL, details: details, fields: fields)
    }

    private struct QuickLookDetails {
        let path: String
        let contentType: String
        let risk: [String]
    }

    private func quickLookDetails(from item: [String: Any]) -> QuickLookDetails? {
        let path = stringish(item["path"]) ?? stringish(item["fs_path"]) ?? stringish(item["file"]) ?? ""
        guard !path.isEmpty else { return nil }
        let contentType = stringish(item["content_type"]) ?? stringish(item["uti"]) ?? ""
        return QuickLookDetails(path: path, contentType: contentType, risk: quickLookRisk(item: item, path: path))
    }

    private func quickLookRisk(item: [String: Any], path: String) -> [String] {
        var risk = (stringish(item["risk_tags"]) ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let lower = path.lowercased()
        if ["password", "secret", "credential", "id_rsa", ".pem", "ssn"].contains(where: lower.contains) {
            appendRisk("sensitive_path", to: &risk)
            appendRisk("credential_filename", to: &risk)
        }
        if ["evil", "payload", "implant"].contains(where: lower.contains) { appendRisk("suspicious_name", to: &risk) }
        return risk
    }

    private func appendRisk(_ tag: String, to risk: inout [String]) {
        if !risk.contains(tag) { risk.append(tag) }
    }

    private func quickLookFields(item: [String: Any], details: QuickLookDetails) -> [String: String] {
        var fields = ["ql.path": details.path, "ql.content_type": details.contentType, FieldTaxonomy.eventType: "filesystem.quicklook"]
        if let mtime = stringish(item["mtime"]) { fields["ql.mtime"] = mtime }
        if let hits = stringish(item["hit_count"]) ?? stringish(item["hits"]) { fields["ql.hit_count"] = hits }
        if !details.risk.isEmpty { fields["ql.risk_tags"] = details.risk.joined(separator: ",") }
        return fields
    }

    private func quickLookEnvelope(item: [String: Any], sourceURL: URL, details: QuickLookDetails, fields: [String: String]) -> EventEnvelope {
        EventEnvelope(identity: EventEnvelope.Identity(kind: "filesystem.quicklook", label: "QUICKLOOK"), capture: EventEnvelope.Capture(source: .parser, eventTime: parseDate(item["mtime"]) ?? Date(timeIntervalSince1970: 0), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: [.file(path: details.path)], properties: fields, provenance: ArtifactRoot.pathKey(sourceURL), confidence: 0.88))
    }
}
