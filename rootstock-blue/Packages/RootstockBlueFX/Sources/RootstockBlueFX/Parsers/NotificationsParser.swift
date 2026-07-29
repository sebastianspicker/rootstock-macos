import Foundation
import RootstockBlueCore

/// Notification Center inventory - **metadata markers only**.
///
/// Emits app_id, category, title markers, and delivery times.
/// Does not export full notification body content into case JSONL by default
/// (privacy non-goal: no full message-body dumps).
public struct NotificationsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "NOTIFICATIONS",
        tier: .tier2,
        description: "Notification Center metadata markers (no full body dumps)"
    )

    /// Body-like keys that must never be copied into envelopes.
    private static let forbiddenBodyKeys: Set<String> = [
        "body", "message", "subtitle", "userinfo", "user_info",
        "content", "text", "alert_body", "full_text", "notification_body",
    ]

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/notification_center.json",
            "Library/Preferences/notifications.json",
            "Library/Logs/notification_center.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "notification_center.json"
                || name == "notifications.json"
                || name == "notification_center.jsonl"
                || name == "db2-export.json"
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
            nestedKeys: ["notifications", "items", "entries"],
            identityKeys: ["app_id", "bundle_id"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let details = notificationDetails(from: item)
        guard !details.appID.isEmpty || !details.titleMarker.isEmpty else { return nil }
        let fields = notificationFields(item: item, details: details)
        return notificationEnvelope(item: item, sourceURL: sourceURL, details: details, fields: fields)
    }

    private struct NotificationDetails {
        let appID: String
        let category: String
        let titleMarker: String
        let risk: [String]
    }

    private func notificationDetails(from item: [String: Any]) -> NotificationDetails {
        ignoreForbiddenBodyKeys(in: item)
        let appID = stringish(item["app_id"]) ?? stringish(item["bundle_id"]) ?? stringish(item["identifier"]) ?? ""
        let category = stringish(item["category"]) ?? stringish(item["thread"]) ?? ""
        let title = stringish(item["title_marker"]) ?? stringish(item["title"]) ?? stringish(item["headline"]) ?? ""
        let titleMarker = String(title.prefix(120))
        return NotificationDetails(appID: appID, category: category, titleMarker: titleMarker, risk: notificationRisk(item: item, appID: appID, titleMarker: titleMarker))
    }

    private func ignoreForbiddenBodyKeys(in item: [String: Any]) {
        for key in item.keys where Self.forbiddenBodyKeys.contains(key.lowercased()) { _ = key }
    }

    private func notificationRisk(item: [String: Any], appID: String, titleMarker: String) -> [String] {
        var risk = (stringish(item["risk_tags"]) ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        if ["evil", "implant", "malware"].contains(where: appID.lowercased().contains) { appendRisk("suspicious_app", to: &risk) }
        if ["remote access", "password", "credential", "security"].contains(where: titleMarker.lowercased().contains) { appendRisk("security_sensitive", to: &risk) }
        return risk
    }

    private func appendRisk(_ tag: String, to risk: inout [String]) {
        if !risk.contains(tag) { risk.append(tag) }
    }

    private func notificationFields(item: [String: Any], details: NotificationDetails) -> [String: String] {
        var fields = ["notif.app_id": details.appID, "notif.category": details.category, "notif.title_marker": details.titleMarker, "notif.body_exported": boolish(item["body_exported"]) == true ? "true" : "false", FieldTaxonomy.eventType: "notification.delivered"]
        if let delivered = stringish(item["delivered_at"]) ?? stringish(item["timestamp"]) { fields["notif.delivered_at"] = delivered }
        if let hasBody = boolish(item["has_body"]) { fields["notif.has_body"] = hasBody ? "true" : "false" }
        if !details.risk.isEmpty { fields["notif.risk_tags"] = details.risk.joined(separator: ",") }
        fields.removeValue(forKey: "notif.body")
        fields.removeValue(forKey: "body")
        fields.removeValue(forKey: "message")
        return fields
    }

    private func notificationEnvelope(item: [String: Any], sourceURL: URL, details: NotificationDetails, fields: [String: String]) -> EventEnvelope {
        EventEnvelope(identity: EventEnvelope.Identity(kind: "notification.delivered", label: "NOTIFICATIONS"), capture: EventEnvelope.Capture(source: .parser, eventTime: parseDate(item["delivered_at"] ?? item["timestamp"]) ?? Date(timeIntervalSince1970: 0), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: [EntityID(kind: .host, value: "notif|\(details.appID)")], properties: fields, provenance: ArtifactRoot.pathKey(sourceURL), confidence: 0.88))
    }
}
