import Foundation
import RootstockBlueCore

/// Browser cookie **domain inventory** - session/domain risk without secret values.
///
/// Emits domain, name markers, secure/httpOnly flags, and risk tags.
/// Does not export raw cookie values (privacy / anti-hijack non-goal).
public struct CookiesParser: ArtifactParser {
    private struct CookieMetadata {
        let domain: String
        let nameMarker: String
        let engine: String
        let path: String
        let secure: Bool
        let httpOnly: Bool
        let sameSite: String
        let user: String
    }

    public let manifest = PluginManifest(
        id: "COOKIES",
        tier: .tier2,
        description: "Browser cookie domain inventory (no raw session values)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/cookies_inventory.json",
            "Library/Preferences/browser_cookies.json",
            "Library/Logs/cookies_export.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "cookies_inventory.json"
                || name == "browser_cookies.json"
                || name == "cookies_export.jsonl"
                || name == "Cookies.json"
        }) where seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["cookies", "items", "entries"],
            identityKeys: ["domain", "host"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let domain = cookieValue(item, keys: ["domain", "host", "cookie.domain"])
        let nameMarker = cookieValue(item, keys: ["name_marker", "name", "cookie_name"])
        let engine = cookieValue(item, keys: ["engine", "browser", "browser.engine"])
        let path = stringish(item["path"]) ?? "/"
        let secure = boolish(item["secure"]) ?? boolish(item["is_secure"]) ?? false
        let httpOnly = boolish(item["http_only"])
            ?? boolish(item["httponly"])
            ?? boolish(item["httpOnly"])
            ?? false
        let sameSite = stringish(item["same_site"]) ?? stringish(item["samesite"]) ?? ""

        guard !domain.isEmpty || !nameMarker.isEmpty else { return nil }

        let risk = riskTags(for: item, domain: domain, nameMarker: nameMarker, secure: secure)

        let user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""
        let metadata = CookieMetadata(
            domain: domain,
            nameMarker: nameMarker,
            engine: engine,
            path: path,
            secure: secure,
            httpOnly: httpOnly,
            sameSite: sameSite,
            user: user
        )
        let fields = cookieFields(item, metadata: metadata, risk: risk)

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "browser.cookie",
                label: "COOKIES"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["created"] ?? item["last_access"] ?? item["timestamp"])
                ?? Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [
                EntityID(kind: .network, value: "cookie|\(domain)"),
            ],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private func cookieValue(_ item: [String: Any], keys: [String]) -> String {
        keys.lazy.compactMap { stringish(item[$0]) }.first ?? ""
    }

    private func riskTags(for item: [String: Any], domain: String, nameMarker: String, secure: Bool) -> [String] {
        var tags = stringish(item["risk_tags"])?.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        } ?? []
        let lowerDomain = domain.lowercased()
        append("evil_domain", when: ["evil", "malware", "c2."].contains { lowerDomain.contains($0) } || lowerDomain.hasSuffix(".evil"), to: &tags)
        append("suspicious_domain", when: ["pastebin", "ngrok", "trycloudflare"].contains { lowerDomain.contains($0) }, to: &tags)
        let lowerName = nameMarker.lowercased()
        append("session_cookie", when: ["session", "sid", "auth", "token"].contains { lowerName.contains($0) }, to: &tags)
        append("insecure_flag", when: !secure && (tags.contains("session_cookie") || tags.contains("evil_domain")), to: &tags)
        return tags
    }

    private func append(_ tag: String, when condition: Bool, to tags: inout [String]) {
        if condition, !tags.contains(tag) {
            tags.append(tag)
        }
    }

    private func cookieFields(
        _ item: [String: Any],
        metadata: CookieMetadata,
        risk: [String]
    ) -> [String: String] {
        var fields: [String: String] = [
            "cookie.domain": metadata.domain,
            "cookie.name_marker": String(metadata.nameMarker.prefix(80)),
            "cookie.path": metadata.path,
            "cookie.secure": metadata.secure ? "true" : "false",
            "cookie.http_only": metadata.httpOnly ? "true" : "false",
            "cookie.same_site": metadata.sameSite,
            "cookie.engine": metadata.engine,
            "cookie.value_exported": "false",
            FieldTaxonomy.eventType: "browser.cookie",
            FieldTaxonomy.browserName: metadata.engine,
            FieldTaxonomy.userName: metadata.user,
        ]
        if let expires = stringish(item["expires"]) ?? stringish(item["expiry"]) {
            fields["cookie.expires"] = expires
        }
        if !risk.isEmpty {
            fields["cookie.risk_tags"] = risk.joined(separator: ",")
        }
        return fields
    }
}
