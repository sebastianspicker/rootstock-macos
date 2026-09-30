import Foundation
import RootstockBlueCore

/// Screen Time / Focus markers - app usage inventory and focus-mode posture.
///
/// Metadata only: app_id, category, usage_seconds, focus mode. Does not dump
/// private activity content or full knowledgeC-style message bodies.
public struct ScreenTimeParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SCREENTIME",
        tier: .tier2,
        description: "Screen Time / Focus markers (app usage inventory, not private content)"
    )

    private struct ScreenTimeApp {
        let id: String
        let bundlePath: String
        let category: String
        let usage: String
        let focusMode: String
    }

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/screentime_markers.json",
            "Library/Preferences/screentime.json",
            "Library/Preferences/screen_time.json",
            "Library/Logs/screentime_export.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "screentime_markers.json"
                || name == "screentime.json"
                || name == "screen_time.json"
                || name == "screentime_export.jsonl"
        }) where seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        guard let object = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        if let dictionary = object as? [String: Any] {
            return screenTimeEvents(from: dictionary, sourceURL: url)
        }
        guard let items = object as? [[String: Any]] else { return [] }
        return items.compactMap { makeAppEvent(from: $0, sourceURL: url) }
    }

    private func screenTimeEvents(from dictionary: [String: Any], sourceURL: URL) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        events.append(contentsOf: appEvents(dictionary["apps"], sourceURL: sourceURL))
        events.append(contentsOf: focusEvents(dictionary["focus"], sourceURL: sourceURL))
        events.append(contentsOf: appEvents(dictionary["items"], sourceURL: sourceURL))
        if dictionary["app_id"] != nil, let event = makeAppEvent(from: dictionary, sourceURL: sourceURL) {
            events.append(event)
        }
        return events
    }

    private func appEvents(_ value: Any?, sourceURL: URL) -> [EventEnvelope] {
        guard let items = value as? [[String: Any]] else { return [] }
        return items.compactMap { makeAppEvent(from: $0, sourceURL: sourceURL) }
    }

    private func focusEvents(_ value: Any?, sourceURL: URL) -> [EventEnvelope] {
        guard let items = value as? [[String: Any]] else { return [] }
        return items.compactMap { makeFocusEvent(from: $0, sourceURL: sourceURL) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for obj in ArtifactIO.jsonlDictionaries(contentsOf: url) {
            if obj["mode"] != nil || obj["focus_mode"] != nil, obj["app_id"] == nil {
                if let e = makeFocusEvent(from: obj, sourceURL: url) { events.append(e) }
            } else if let e = makeAppEvent(from: obj, sourceURL: url) {
                events.append(e)
            }
        }
        return events
    }

    private func makeAppEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let app = ScreenTimeApp(
            id: stringish(item["app_id"]) ?? stringish(item["bundle_id"]) ?? stringish(item["identifier"]) ?? "",
            bundlePath: stringish(item["bundle_path"]) ?? stringish(item["path"]) ?? "",
            category: stringish(item["category"]) ?? "",
            usage: stringish(item["usage_seconds"]) ?? stringish(item["usage"]) ?? "",
            focusMode: stringish(item["focus_mode"]) ?? ""
        )
        guard !app.id.isEmpty else { return nil }

        let risk = screenTimeRiskTags(item: item, appID: app.id, bundlePath: app.bundlePath, usage: app.usage)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "pol.screentime",
                label: "SCREENTIME"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["last_used"]) ?? Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "screentime|\(app.id)")],
                properties: screenTimeFields(item: item, app: app, risk: risk),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.86
            )
        )
    }

    private func screenTimeRiskTags(
        item: [String: Any],
        appID: String,
        bundlePath: String,
        usage: String
    ) -> [String] {
        var risk = screenTimeItemRiskTags(item)
        let lowerApp = appID.lowercased()
        let lowerPath = bundlePath.lowercased()
        if ["evil", "implant", "malware"].contains(where: lowerApp.contains) {
            appendScreenTimeRiskTag("suspicious_app", to: &risk)
        }
        if lowerPath.contains("/tmp/") || lowerPath.hasPrefix("/var/tmp") {
            appendScreenTimeRiskTag("tmp_path", to: &risk)
        }
        if let seconds = Double(usage), seconds >= 3600 {
            appendScreenTimeRiskTag("high_usage", to: &risk)
        }
        return risk
    }

    private func screenTimeItemRiskTags(_ item: [String: Any]) -> [String] {
        guard let tags = stringish(item["risk_tags"]), !tags.isEmpty else { return [] }
        return tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
    }

    private func appendScreenTimeRiskTag(_ tag: String, to risk: inout [String]) {
        guard !risk.contains(tag) else { return }
        risk.append(tag)
    }

    private func screenTimeFields(
        item: [String: Any],
        app: ScreenTimeApp,
        risk: [String]
    ) -> [String: String] {
        var fields: [String: String] = [
            "screentime.app_id": app.id,
            "screentime.bundle_path": app.bundlePath,
            "screentime.category": app.category,
            "screentime.usage_seconds": app.usage,
            "screentime.focus_mode": app.focusMode,
            FieldTaxonomy.eventType: "pol.screentime",
        ]
        if let lastUsed = stringish(item["last_used"]) {
            fields["screentime.last_used"] = lastUsed
        }
        if !risk.isEmpty {
            fields["screentime.risk_tags"] = risk.joined(separator: ",")
        }
        return fields
    }

    private func makeFocusEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let mode = stringish(item["mode"])
            ?? stringish(item["focus_mode"])
            ?? ""
        guard !mode.isEmpty else { return nil }
        let enabled = boolish(item["enabled"]) ?? true

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "pol.focus",
                label: "SCREENTIME"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["last_changed"]) ?? Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "focus|\(mode)")],
                properties: [
                "screentime.focus_mode": mode,
                "screentime.focus_enabled": enabled ? "true" : "false",
                FieldTaxonomy.eventType: "pol.focus",
            ],
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.85
            )
        )
    }
}
