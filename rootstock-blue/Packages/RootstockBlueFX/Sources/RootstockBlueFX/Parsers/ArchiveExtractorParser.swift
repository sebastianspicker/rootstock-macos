import Foundation
import RootstockBlueCore

/// Third-party archive extractor / quarantine non-inheritance surface (Wave-8 residual pair).
///
/// Inventories extractor apps and drop hints from offline markers.
/// Does not strip quarantine attributes or craft bypass archives.
public struct ArchiveExtractorParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "ARCHIVEEXTRACTOR",
        tier: .tier2,
        description: "Archive quarantine extractor surface (third-party vs stock)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/archive_extractors.json",
            "Library/Logs/archive_extractors.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "archive_extractors.json" || name == "archive_extractors.jsonl"
        }) where seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return ArtifactIO.jsonlDictionaries(contentsOf: url)
                .compactMap { makeEvent(from: $0, sourceURL: url) }
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["extractors", "items", "entries"],
            identityKeys: ["extractor_name", "name", "extractor_path", "path"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private struct ArchiveDetails {
        let name: String
        let path: String
        let thirdParty: Bool
        let dropHint: String
        let user: String
        let risk: [String]
    }

    private func itemString(_ item: [String: Any], keys: [String]) -> String? {
        keys.lazy.compactMap { stringish(item[$0]) }.first
    }

    private func riskTags(_ item: [String: Any], thirdParty: Bool) -> [String] {
        var tags = (stringish(item["risk_tags"]) ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
        if thirdParty {
            for tag in ["third_party_extractor", "quarantine_non_inherit"] where !tags.contains(tag) {
                tags.append(tag)
            }
        }
        return tags
    }

    private func archiveFields(_ details: ArchiveDetails) -> [String: String] {
        var fields: [String: String] = [
            "archive.extractor_name": details.name,
            "archive.extractor_path": details.path,
            "archive.third_party": details.thirdParty ? "true" : "false",
            "archive.drop_hint": details.dropHint,
            FieldTaxonomy.eventType: "archive.extractor",
            FieldTaxonomy.userName: details.user,
        ]
        if !details.risk.isEmpty { fields["archive.risk_tags"] = details.risk.joined(separator: ",") }
        return fields
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        var name = itemString(item, keys: ["extractor_name", "name", "app"]) ?? ""
        let path = itemString(item, keys: ["extractor_path", "path", "app_path"]) ?? ""
        if name.isEmpty, !path.isEmpty {
            name = URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
        }
        guard !name.isEmpty || !path.isEmpty else { return nil }
        if name.isEmpty { name = "unknown" }
        let thirdParty = boolish(item["third_party"]) ?? inferThirdParty(name: name, path: path)
        let details = ArchiveDetails(
            name: name,
            path: path,
            thirdParty: thirdParty,
            dropHint: itemString(item, keys: ["drop_hint", "drop_path", "downloads_hint"]) ?? "",
            user: itemString(item, keys: ["user"]) ?? inferUser(from: sourceURL.path) ?? "",
            risk: riskTags(item, thirdParty: thirdParty)
        )
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "archive.extractor",
                label: "ARCHIVEEXTRACTOR"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "archive|\(name.lowercased())|\(thirdParty)")],
                properties: archiveFields(details),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private func inferThirdParty(name: String, path: String) -> Bool {
        let p = path.lowercased()
        let n = name.lowercased()
        if p.contains("/system/library/") || p.hasPrefix("/usr/bin/") {
            return false
        }
        let third = ["keka", "the unarchiver", "betterzip", "archiver", "izip",
                     "stuffit", "winzip", "commander one", "path finder"]
        if third.contains(where: { n.contains($0) || p.contains($0.replacingOccurrences(of: " ", with: "")) }) {
            return true
        }
        // Applications/ outside stock Archive Utility → treat as third-party by default
        if p.contains("/applications/") && !p.contains("archive utility") {
            return true
        }
        return false
    }
}
