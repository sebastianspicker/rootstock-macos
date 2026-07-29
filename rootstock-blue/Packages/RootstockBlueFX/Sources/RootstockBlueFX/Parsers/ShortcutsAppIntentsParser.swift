import Foundation
import RootstockBlueCore

/// Shortcuts / App Intents automation markers (Wave-11 red↔blue pair).
///
/// Inventories Shortcuts database / App Intents framework path markers for IR.
/// Honesty: never runs shortcuts or forges intents.
public struct ShortcutsAppIntentsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SHORTCUTSAPPINTENTS",
        tier: .tier2,
        description: "Shortcuts / App Intents automation lateral markers"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/shortcuts_app_intents.json",
            "Library/Logs/shortcuts_app_intents.jsonl",
            "Library/Shortcuts/shortcuts_inventory.json",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "shortcuts_app_intents.json"
                || name == "shortcuts_app_intents.jsonl"
                || name == "shortcuts_inventory.json"
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
            nestedKeys: ["items", "shortcuts", "entries", "automations"],
            identityKeys: ["shortcut_name", "path", "automation_path", "intent_path"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        guard let details = shortcutDetails(from: item) else { return nil }
        let fields = shortcutFields(item: item, details: details, sourceURL: sourceURL)
        return shortcutEnvelope(item: item, sourceURL: sourceURL, details: details, fields: fields)
    }

    private struct ShortcutDetails {
        let path: String
        let name: String
        let risk: [String]
    }

    private func shortcutDetails(from item: [String: Any]) -> ShortcutDetails? {
        let path = stringish(item["path"]) ?? stringish(item["automation_path"]) ?? stringish(item["intent_path"]) ?? stringish(item["shortcuts_path"]) ?? ""
        let name = stringish(item["shortcut_name"]) ?? stringish(item["name"]) ?? ""
        guard !path.isEmpty || !name.isEmpty else { return nil }
        return ShortcutDetails(path: path, name: name, risk: shortcutRisk(item: item, path: path))
    }

    private func shortcutRisk(item: [String: Any], path: String) -> [String] {
        var risk = (stringish(item["risk_tags"]) ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        if boolish(item["automation_surface"]) == true || !path.isEmpty { appendRisk("automation_surface", to: &risk) }
        if boolish(item["runs_shell"]) == true || boolish(item["scripting"]) == true { appendRisk("scripting_action", to: &risk) }
        if boolish(item["remote_adjacent"]) == true { appendRisk("remote_adjacent", to: &risk) }
        return risk
    }

    private func appendRisk(_ tag: String, to risk: inout [String]) {
        if !risk.contains(tag) { risk.append(tag) }
    }

    private func shortcutFields(item: [String: Any], details: ShortcutDetails, sourceURL: URL) -> [String: String] {
        let user = stringish(item["user"]) ?? inferUser(from: details.path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields = ["shortcuts.path": details.path, "shortcuts.name": details.name, "shortcuts.notes": stringish(item["notes"]) ?? "Shortcuts/App Intents path markers - never executes automations", FieldTaxonomy.eventType: "shortcuts.automation", FieldTaxonomy.userName: user]
        if !details.risk.isEmpty { fields["shortcuts.risk_tags"] = details.risk.joined(separator: ",") }
        return fields
    }

    private func shortcutEnvelope(item: [String: Any], sourceURL: URL, details: ShortcutDetails, fields: [String: String]) -> EventEnvelope {
        EventEnvelope(identity: EventEnvelope.Identity(kind: "shortcuts.automation", label: "SHORTCUTSAPPINTENTS"), capture: EventEnvelope.Capture(source: .parser, eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: [EntityID(kind: .host, value: "shortcuts|\(details.name.isEmpty ? details.path : details.name)")], properties: fields, provenance: ArtifactRoot.pathKey(sourceURL), confidence: 0.88))
    }
}
