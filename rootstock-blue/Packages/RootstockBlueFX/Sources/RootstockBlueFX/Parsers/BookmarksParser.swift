import Foundation
import RootstockBlueCore

/// Browser bookmarks inventory - URL/title/folder PoL for IR narrative.
///
/// Surfaces evil-domain and suspicious bookmarks as first-class case events
/// shared across Safari/Chromium/Firefox engines.
public struct BookmarksParser: ArtifactParser {
    private struct BookmarkDetails {
        let url: String
        let title: String
        let folder: String
        let engine: String
        let user: String
        let risk: [String]
    }

    public let manifest = PluginManifest(
        id: "BOOKMARKS",
        tier: .tier2,
        description: "Browser bookmarks inventory (URL/title/folder with risk tags)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        appendEvents(from: standardURLs(in: root), to: &events, seen: &seen)
        appendEvents(from: discoveredURLs(in: root), to: &events, seen: &seen)

        return events
    }

    private func standardURLs(in root: ArtifactRoot) -> [URL] {
        [
            "Library/Preferences/bookmarks_inventory.json",
            "Library/Preferences/browser_bookmarks.json",
            "Library/Logs/bookmarks_export.jsonl",
        ].compactMap { root.firstExisting([$0]) }
    }

    private func discoveredURLs(in root: ArtifactRoot) -> [URL] {
        root.enumerate(matching: { Self.isBookmarkArtifact($0) })
    }

    private static func isBookmarkArtifact(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        return name == "bookmarks_inventory.json"
            || name == "browser_bookmarks.json"
            || name == "bookmarks_export.jsonl"
            || name == "Bookmarks.json"
            || (name == "Bookmarks" && url.pathExtension.isEmpty)
    }

    private func appendEvents(from urls: [URL], to events: inout [EventEnvelope], seen: inout PathDeduper) {
        for url in urls where seen.insert(url) {
            events.append(contentsOf: parseFile(at: url))
        }
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["bookmarks", "items", "roots"],
            identityKeys: ["url", "uri"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let urlString = bookmarkValue(item, keys: ["url", "uri", "href"])
        let title = bookmarkValue(item, keys: ["title", "name"])
        let folder = bookmarkValue(item, keys: ["folder", "parent", "path"])
        let engine = bookmarkValue(item, keys: ["engine", "browser"])

        guard !urlString.isEmpty || !title.isEmpty else { return nil }

        let risk = riskTags(for: item, url: urlString, title: title)

        let user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""
        let details = BookmarkDetails(url: urlString, title: title, folder: folder, engine: engine, user: user, risk: risk)
        let fields = bookmarkFields(details)

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "browser.bookmark",
                label: "BOOKMARKS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["added"] ?? item["date_added"] ?? item["timestamp"])
                ?? Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: urlString.isEmpty
                ? [EntityID(kind: .host, value: "bookmark|\(title)")]
                : [EntityID(kind: .file, value: urlString)],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private func bookmarkValue(_ item: [String: Any], keys: [String]) -> String {
        keys.lazy.compactMap { stringish(item[$0]) }.first ?? ""
    }

    private func riskTags(for item: [String: Any], url: String, title: String) -> [String] {
        var tags = stringish(item["risk_tags"])?.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        } ?? []
        let lower = (url + " " + title).lowercased()
        append("evil_domain", when: ["evil", "malware", "c2."].contains { lower.contains($0) }, to: &tags)
        append("suspicious_domain", when: ["pastebin", "ngrok", "raw.githubusercontent"].contains { lower.contains($0) }, to: &tags)
        append("script_bookmark", when: ["javascript:", "data:"].contains { url.lowercased().hasPrefix($0) }, to: &tags)
        return tags
    }

    private func append(_ tag: String, when condition: Bool, to tags: inout [String]) {
        if condition, !tags.contains(tag) {
            tags.append(tag)
        }
    }

    private func bookmarkFields(_ details: BookmarkDetails) -> [String: String] {
        var fields: [String: String] = [
            "bookmark.url": details.url,
            "bookmark.title": String(details.title.prefix(200)),
            "bookmark.folder": details.folder,
            "bookmark.engine": details.engine,
            FieldTaxonomy.eventType: "browser.bookmark",
            FieldTaxonomy.browserName: details.engine,
            FieldTaxonomy.userName: details.user,
        ]
        if !details.risk.isEmpty {
            fields["bookmark.risk_tags"] = details.risk.joined(separator: ",")
        }
        return fields
    }
}
