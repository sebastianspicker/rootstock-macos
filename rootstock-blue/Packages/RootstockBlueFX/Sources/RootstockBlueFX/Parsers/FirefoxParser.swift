import Foundation
import RootstockBlueCore

/// Firefox browser history and downloads - parity with Safari/Chromium case events.
///
/// Prefers fixture-friendly `firefox_history.json` exports; also reads places.sqlite
/// when present (moz_places / moz_historyvisits / moz_annos download markers).
public struct FirefoxParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "FIREFOX",
        tier: .tier2,
        description: "Firefox places history visits and downloads"
    )

    public init() {}

    private struct VisitDetails {
        let url: String
        let title: String
        let visitCount: String
        let riskTags: [String]
        let eventTime: Date
    }

    private struct DownloadDetails {
        let path: String
        let url: String
        let mimeType: String
        let riskTags: [String]
        let eventTime: Date
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        // JSON inventory exports (primary for fixtures / UAC-style dumps)
        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "firefox_history.json"
                || name == "firefox_export.json"
                || name == "places_export.json"
        }) where seen.insert(url) {
                events.append(contentsOf: parseJSONExport(at: url))
        }

        // places.sqlite when present
        for url in root.enumerate(matching: { url in
            url.lastPathComponent == "places.sqlite"
                && (url.path.contains("Firefox") || url.path.contains("firefox"))
        }) where seen.insert(url) {
                if let rows = try? parsePlacesSQLite(url) {
                    events.append(contentsOf: rows)
                }
        }

        return events
    }

    private func parseJSONExport(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        let user = inferUser(from: url.path)
        if let dict = obj as? [String: Any] {
            return exportEvents(from: dict, sourceURL: url, user: user)
        }
        if let items = obj as? [[String: Any]] {
            return mixedEvents(items, sourceURL: url, user: user)
        }
        return []
    }

    private func exportEvents(from dict: [String: Any], sourceURL: URL, user: String?) -> [EventEnvelope] {
        visitEvents(dict["visits"] as? [[String: Any]] ?? [], sourceURL: sourceURL, user: user)
            + downloadEvents(dict["downloads"] as? [[String: Any]] ?? [], sourceURL: sourceURL, user: user)
            + mixedEvents(dict["items"] as? [[String: Any]] ?? [], sourceURL: sourceURL, user: user)
    }

    private func visitEvents(_ items: [[String: Any]], sourceURL: URL, user: String?) -> [EventEnvelope] {
        items.compactMap { makeVisit(from: $0, sourceURL: sourceURL, user: user) }
    }

    private func downloadEvents(_ items: [[String: Any]], sourceURL: URL, user: String?) -> [EventEnvelope] {
        items.compactMap { makeDownload(from: $0, sourceURL: sourceURL, user: user) }
    }

    private func mixedEvents(_ items: [[String: Any]], sourceURL: URL, user: String?) -> [EventEnvelope] {
        items.compactMap { item in
            isDownload(item) ? makeDownload(from: item, sourceURL: sourceURL, user: user)
                : makeVisit(from: item, sourceURL: sourceURL, user: user)
        }
    }

    private func isDownload(_ item: [String: Any]) -> Bool {
        item["path"] != nil || item["target_path"] != nil
    }

    private func parsePlacesSQLite(_ url: URL) throws -> [EventEnvelope] {
        let reader = try SQLiteReader(url: url)
        let user = inferUser(from: url.path)
        return try historyEvents(reader: reader, sourceURL: url, user: user)
            + downloadAnnotationEvents(reader: reader, sourceURL: url, user: user)
    }

    private func historyEvents(reader: SQLiteReader, sourceURL: URL, user: String?) throws -> [EventEnvelope] {
        guard try reader.tableExists("moz_places"), try reader.tableExists("moz_historyvisits") else { return [] }
        let rows = try reader.query(
                """
                SELECT
                  COALESCE(p.url, '') AS url,
                  COALESCE(p.title, '') AS title,
                  COALESCE(CAST(p.visit_count AS TEXT), '') AS visit_count,
                  COALESCE(CAST(v.visit_date AS TEXT), '') AS visit_date
                FROM moz_historyvisits v
                LEFT JOIN moz_places p ON v.place_id = p.id
                LIMIT 5000;
                """
        )
        return rows.map { makeSQLiteVisit($0, sourceURL: sourceURL, user: user) }
    }

    private func makeSQLiteVisit(_ row: [String: String], sourceURL: URL, user: String?) -> EventEnvelope {
        let url = row["url"] ?? ""
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "browser.visit",
                label: "FIREFOX"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: firefoxDate(row["visit_date"]),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: url.isEmpty ? [] : [EntityID(kind: .file, value: url)],
                properties: visitFields(url: url, title: row["title"] ?? "", count: row["visit_count"] ?? "", user: user, riskTags: []),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.95
            )
        )
    }

    private func downloadAnnotationEvents(reader: SQLiteReader, sourceURL: URL, user: String?) throws -> [EventEnvelope] {
        guard try reader.tableExists("moz_annos"), try reader.tableExists("moz_places") else { return [] }
        let rows = try reader.query(
                """
                SELECT
                  COALESCE(p.url, '') AS url,
                  COALESCE(a.content, '') AS content,
                  COALESCE(CAST(a.dateAdded AS TEXT), '') AS date_added
                FROM moz_annos a
                LEFT JOIN moz_places p ON a.place_id = p.id
                WHERE a.content LIKE 'file://%' OR a.content LIKE '/%'
                LIMIT 2000;
                """
        )
        return rows.map { makeSQLiteDownload($0, sourceURL: sourceURL, user: user) }
    }

    private func makeSQLiteDownload(_ row: [String: String], sourceURL: URL, user: String?) -> EventEnvelope {
        let path = (row["content"] ?? "").replacingOccurrences(of: "file://", with: "")
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "browser.download",
                label: "FIREFOX"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: firefoxDate(row["date_added"]),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: downloadEntities(path: path, url: ""),
                properties: downloadFields(path: path, url: row["url"] ?? "", mimeType: "", user: user, riskTags: []),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private func firefoxDate(_ raw: String?) -> Date {
        Epochs.dateFromFirefoxMicroseconds(raw ?? "") ?? Date(timeIntervalSince1970: 0)
    }

    private func makeVisit(from item: [String: Any], sourceURL: URL, user: String?) -> EventEnvelope? {
        guard let details = visitDetails(item) else { return nil }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "browser.visit",
                label: "FIREFOX"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: details.eventTime,
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: visitEntities(details.url),
                properties: visitFields(url: details.url, title: details.title, count: details.visitCount, user: user, riskTags: details.riskTags),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.92
            )
        )
    }

    private func makeDownload(from item: [String: Any], sourceURL: URL, user: String?) -> EventEnvelope? {
        guard let details = downloadDetails(item) else { return nil }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "browser.download",
                label: "FIREFOX"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: details.eventTime,
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: downloadEntities(path: details.path, url: details.url),
                properties: downloadFields(path: details.path, url: details.url, mimeType: details.mimeType, user: user, riskTags: details.riskTags),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.92
            )
        )
    }

    private func visitDetails(_ item: [String: Any]) -> VisitDetails? {
        let url = stringish(item["url"]) ?? stringish(item["uri"]) ?? ""
        let title = stringish(item["title"]) ?? ""
        guard !url.isEmpty || !title.isEmpty else { return nil }
        return VisitDetails(
            url: url, title: title, visitCount: stringish(item["visit_count"]) ?? "",
            riskTags: visitRiskTags(item, url: url),
            eventTime: parseDate(item["visit_time"] ?? item["timestamp"] ?? item["time"]) ?? Date(timeIntervalSince1970: 0)
        )
    }

    private func downloadDetails(_ item: [String: Any]) -> DownloadDetails? {
        let path = firstString(item, keys: ["path", "target_path", "download_path"])
        let url = firstString(item, keys: ["url", "source_url", "referrer"])
        guard !path.isEmpty || !url.isEmpty else { return nil }
        let mimeType = stringish(item["mime_type"]) ?? ""
        return DownloadDetails(
            path: path, url: url, mimeType: mimeType, riskTags: downloadRiskTags(item, path: path, url: url, mimeType: mimeType),
            eventTime: parseDate(item["start_time"] ?? item["timestamp"] ?? item["time"]) ?? Date(timeIntervalSince1970: 0)
        )
    }

    private func firstString(_ item: [String: Any], keys: [String]) -> String {
        for key in keys {
            if let value = stringish(item[key]) { return value }
        }
        return ""
    }

    private func visitRiskTags(_ item: [String: Any], url: String) -> [String] {
        var tags = taggedRisks(item)
        if suspiciousURL(url) { appendUnique("evil_domain", to: &tags) }
        return tags
    }

    private func downloadRiskTags(_ item: [String: Any], path: String, url: String, mimeType: String) -> [String] {
        var tags = taggedRisks(item)
        if suspiciousDownload(path: path, url: url) { appendUnique("evil_domain", to: &tags) }
        if scriptDownload(path: path, mimeType: mimeType) { appendUnique("script_download", to: &tags) }
        if path.lowercased().contains("/tmp/") { appendUnique("tmp_path", to: &tags) }
        return tags
    }

    private func taggedRisks(_ item: [String: Any]) -> [String] {
        guard let tags = stringish(item["risk_tags"]), !tags.isEmpty else { return [] }
        return tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
    }

    private func suspiciousURL(_ url: String) -> Bool {
        let lower = url.lowercased()
        return lower.contains("evil") || lower.contains("c2.") || lower.contains("malware")
    }

    private func suspiciousDownload(path: String, url: String) -> Bool {
        let lowerPath = path.lowercased()
        return url.lowercased().contains("evil") || lowerPath.contains("evil") || lowerPath.contains("payload")
    }

    private func scriptDownload(path: String, mimeType: String) -> Bool {
        let lowerPath = path.lowercased()
        return lowerPath.hasSuffix(".sh") || lowerPath.hasSuffix(".py") || lowerPath.hasSuffix(".command") || mimeType.contains("x-sh")
    }

    private func appendUnique(_ tag: String, to tags: inout [String]) {
        if !tags.contains(tag) { tags.append(tag) }
    }

    private func visitEntities(_ url: String) -> [EntityID] {
        url.isEmpty ? [] : [EntityID(kind: .file, value: url)]
    }

    private func downloadEntities(path: String, url: String) -> [EntityID] {
        var refs: [EntityID] = []
        if !path.isEmpty { refs.append(.file(path: path)) }
        if !url.isEmpty { refs.append(EntityID(kind: .file, value: url)) }
        return refs
    }

    private func visitFields(url: String, title: String, count: String, user: String?, riskTags: [String]) -> [String: String] {
        var fields = [
            "browser.engine": "firefox", "browser.url": url, "browser.title": title,
            "browser.visit_count": count, FieldTaxonomy.eventType: "browser.visit", FieldTaxonomy.userName: user ?? "",
        ]
        if !riskTags.isEmpty { fields["browser.risk_tags"] = riskTags.joined(separator: ",") }
        return fields
    }

    private func downloadFields(path: String, url: String, mimeType: String, user: String?, riskTags: [String]) -> [String: String] {
        var fields = [
            "browser.engine": "firefox", "browser.url": url, "browser.download_path": path,
            "browser.mime_type": mimeType, FieldTaxonomy.eventType: "browser.download", FieldTaxonomy.userName: user ?? "",
        ]
        if !riskTags.isEmpty { fields["browser.risk_tags"] = riskTags.joined(separator: ",") }
        return fields
    }
}
