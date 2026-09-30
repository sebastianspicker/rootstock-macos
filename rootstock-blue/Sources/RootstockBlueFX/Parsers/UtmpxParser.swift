import Foundation
import RootstockBlueCore

/// Login session records from fixture-friendly utmpx/wtmp JSONL exports.
///
/// Binary utmpx is platform-specific; collectors typically dump JSONL under
/// `private/var/run/utmpx.jsonl`, `var/log/wtmp.jsonl`, or `Library/Logs/utmpx_export.jsonl`.
public struct UtmpxParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "UTMPX",
        tier: .tier1,
        description: "utmpx/wtmp login session records (JSONL export)"
    )

    public init() {}

    private struct SessionDetails {
        let user: String
        let tty: String
        let host: String
        let pid: String
        let eventType: String
        let authType: String
        let remote: Bool
        let eventTime: Date
        let sourceURL: URL
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        return parseRecords(discoveredURLs(root) + knownURLs(root))
    }

    private func discoveredURLs(_ root: ArtifactRoot) -> [URL] {
        var urls: [URL] = []
        var seen = PathDeduper()
        for found in root.enumerate(matching: isUtmpxRecord) {
            if !seen.insert(found) { continue }
            ArtifactRoot.appendUnique(&urls, found)
        }
        return urls
    }

    private func isUtmpxRecord(_ url: URL) -> Bool {
        ["utmpx.jsonl", "wtmp.jsonl", "utmpx_export.jsonl", "btmp.jsonl", "lastlog.jsonl", "utmpx.json", "wtmp.json"].contains(url.lastPathComponent)
    }

    private func knownURLs(_ root: ArtifactRoot) -> [URL] {
        var urls: [URL] = []
        var seen = PathDeduper()
        for rel in [
            "private/var/run/utmpx.jsonl",
            "var/run/utmpx.jsonl",
            "var/log/wtmp.jsonl",
            "private/var/log/wtmp.jsonl",
            "Library/Logs/utmpx_export.jsonl",
        ] {
            if let u = root.firstExisting([rel]) {
                if seen.insert(u) {
                    ArtifactRoot.appendUnique(&urls, u)
                }
            }
        }
        return urls
    }

    private func parseRecords(_ urls: [URL]) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for url in urls {
            if url.pathExtension == "jsonl" || url.lastPathComponent.hasSuffix(".jsonl") {
                events.append(contentsOf: parseJSONL(at: url))
            } else {
                events.append(contentsOf: parseJSON(at: url))
            }
        }
        return events
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSON(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        let entries = ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["records", "entries"]
        )
        return entries.compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        guard let details = sessionDetails(item, sourceURL: sourceURL) else { return nil }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: details.eventType,
                label: "UTMPX"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: details.eventTime,
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: sessionEntities(details),
                properties: sessionFields(details),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.91
            )
        )
    }

    private func sessionDetails(_ item: [String: Any], sourceURL: URL) -> SessionDetails? {
        let user = firstString(item, keys: ["user", "user_name", "username", "ut_user"])
        let tty = firstString(item, keys: ["tty", "line", "ut_line"])
        let host = firstString(item, keys: ["host", "hostname", "ut_host"])
        let type = firstString(item, keys: ["type", "ut_type", "event"])
        guard !user.isEmpty || !type.isEmpty || !tty.isEmpty else { return nil }
        let mapped = mapType(type, item: item)
        return SessionDetails(
            user: user, tty: tty, host: host, pid: firstString(item, keys: ["pid", "ut_pid"]),
            eventType: mapped.eventType, authType: mapped.authType, remote: isRemote(item, host: host),
            eventTime: parseDate(item["timestamp"] ?? item["time"] ?? item["tv_sec"] ?? item["login_time"]) ?? fileMTime(sourceURL), sourceURL: sourceURL
        )
    }

    private func firstString(_ item: [String: Any], keys: [String]) -> String {
        keys.lazy.compactMap { stringValue(item[$0]) }.first ?? ""
    }

    private func isRemote(_ item: [String: Any], host: String) -> Bool {
        if let flag = item["remote"] as? Bool { return flag }
        if let number = item["remote"] as? NSNumber { return number.boolValue }
        if let value = item["remote"] as? String { return ["true", "1", "yes"].contains(value.lowercased()) }
        return !host.isEmpty && host != "localhost" && host != ":" && host != ":0"
    }

    private func sessionFields(_ details: SessionDetails) -> [String: String] {
        var fields: [String: String] = [
            "auth.tty": details.tty, "auth.host": details.host, "auth.type": details.authType,
            FieldTaxonomy.eventType: details.eventType, FieldTaxonomy.filePath: ArtifactRoot.pathKey(details.sourceURL),
        ]
        fields["auth.remote"] = details.remote ? "true" : "false"
        if !details.user.isEmpty {
            fields[FieldTaxonomy.userName] = details.user
            fields["auth.user"] = details.user
        }
        if !details.pid.isEmpty {
            fields["auth.pid"] = details.pid
        }
        return fields
    }

    private func sessionEntities(_ details: SessionDetails) -> [EntityID] {
        var entities: [EntityID] = [
            EntityID(kind: .auth, value: "\(details.authType)|\(details.user)|\(details.tty)|\(details.host)"),
        ]
        if !details.user.isEmpty {
            entities.append(.user(name: details.user))
        }
        if !details.host.isEmpty {
            entities.append(EntityID(kind: .network, value: "host=\(details.host)"))
        }
        return entities
    }

    private func mapType(_ raw: String, item: [String: Any]) -> (eventType: String, authType: String) {
        let lower = raw.lowercased()
        if let number = Int(raw) { return numericType(number) }
        if let event = classifiedType(lower, label: raw) { return event }
        if let action = stringValue(item["action"])?.lowercased(), let event = classifiedType(action, label: action) { return event }
        return ("auth.session", raw.isEmpty ? "session" : raw)
    }

    private func numericType(_ number: Int) -> (eventType: String, authType: String) {
        let types: [Int: (String, String)] = [7: ("auth.login", "USER_PROCESS"), 8: ("auth.logout", "DEAD_PROCESS"), 6: ("auth.session", "INIT_PROCESS"), 5: ("auth.login", "LOGIN_PROCESS"), 2: ("auth.boot", "BOOT_TIME")]
        return types[number] ?? ("auth.session", "UTMPX_\(number)")
    }

    private func classifiedType(_ value: String, label: String) -> (eventType: String, authType: String)? {
        if hasLogoutSignal(value) { return ("auth.logout", label.isEmpty ? "logout" : label) }
        if hasLoginSignal(value) { return ("auth.login", label.isEmpty ? "login" : label) }
        if value.contains("boot") { return ("auth.boot", label) }
        return nil
    }

    private func hasLogoutSignal(_ value: String) -> Bool {
        value.contains("logout") || value.contains("dead") || value == "out"
    }

    private func hasLoginSignal(_ value: String) -> Bool {
        value.contains("login") || value.contains("user_process") || value == "in"
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
