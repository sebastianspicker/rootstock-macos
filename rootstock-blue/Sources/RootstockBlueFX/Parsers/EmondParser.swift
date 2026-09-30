import Foundation
import RootstockBlueCore

/// Event Monitor Daemon (emond) rules - classic macOS persistence (ATT&CK T1546.014).
///
/// mac_apt / KnockKnock-class examiners still expect emond.d inventory even though
/// Apple has reduced emond prominence; offline images and older fleets retain it.
///
/// Significant improvement over a CSV dump: normalized `persistence.item` envelopes,
/// entity IDs, and action/command extraction from plist + JSON fixtures for CI.
public struct EmondParser: ArtifactParser {
    private struct RuleDetails {
        let name: String
        let command: String
        let enabled: String
        let eventTypes: String
        let path: String
        let extra: [String: String]
    }

    public let manifest = PluginManifest(
        id: "EMOND",
        tier: .tier1,
        description: "Event Monitor Daemon (emond) rules under /etc/emond.d"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        appendInventoryEvents(from: root, to: &events, seen: &seen)
        appendRuleEvents(from: root, to: &events, seen: &seen)

        return events
    }

    private func appendInventoryEvents(from root: ArtifactRoot, to events: inout [EventEnvelope], seen: inout PathDeduper) {
        let paths = [
            "etc/emond.d/rules.json",
            "private/etc/emond.d/rules.json",
            "Library/Preferences/emond_rules.json",
        ]
        for path in paths {
            guard let url = root.firstExisting([path]),
                  let json = ArtifactIO.jsonObject(contentsOf: url),
                  seen.insert(url)
            else { continue }
            events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
        }
    }

    private func appendRuleEvents(from root: ArtifactRoot, to events: inout [EventEnvelope], seen: inout PathDeduper) {
        for url in root.enumerate(matching: { Self.isRuleFile($0) }) where seen.insert(url) {
            events.append(contentsOf: parseRuleFile(at: url))
        }
    }

    private static func isRuleFile(_ url: URL) -> Bool {
        let path = url.path
        guard (path.contains("/emond.d/") || path.contains("/emond/")), !url.hasDirectoryPath else { return false }
        let name = url.lastPathComponent
        return name.hasSuffix(".plist")
            || name.hasSuffix(".json")
            || name.hasSuffix(".rules")
            || (path.contains("/emond.d/rules/") && !name.hasPrefix("."))
    }

    private func parseRuleFile(at url: URL) -> [EventEnvelope] {
        let key = ArtifactRoot.pathKey(url)
        if url.pathExtension == "json", let json = ArtifactIO.jsonObject(contentsOf: url) {
            return parseJSONInventory(json, rawRef: key)
        }
        if url.pathExtension == "plist" || isBinaryOrXMLPlist(url) {
            return parsePlistRule(at: url)
        }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return parseTextRule(at: url, text: text)
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        var items = ArtifactIO.dictionaryEntries(
            from: json,
            nestedKeys: ["rules", "emond_rules"]
        )
        if items.isEmpty, let dict = json as? [String: Any] {
            items = [dict]
        } else if items.isEmpty, let arr = json as? [[String: Any]] {
            items = arr
        }
        return items.compactMap { item in
            let name = stringish(item["name"]) ?? stringish(item["label"]) ?? "unnamed"
            let action = stringish(item["action"])
                ?? stringish(item["command"])
                ?? stringish(item["program"])
                ?? ""
            let enabled = boolish(item["enabled"]).map { $0 ? "true" : "false" } ?? "unknown"
            let eventTypes = stringish(item["eventTypes"])
                ?? stringish(item["event_types"])
                ?? (item["eventTypes"] as? [Any])?.compactMap { stringish($0) }.joined(separator: ",")
                ?? ""
            return makeEvent(RuleDetails(
                name: name,
                command: action.isEmpty ? name : action,
                enabled: enabled,
                eventTypes: eventTypes,
                path: rawRef,
                extra: item.compactMapValues { stringish($0) }
            ))
        }
    }

    private func parsePlistRule(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url),
              let obj = ArtifactIO.plistObject(from: data)
        else { return [] }

        let pathKey = ArtifactRoot.pathKey(url)
        if let arr = obj as? [[String: Any]] {
            return arr.compactMap { dict in
                eventFromPlistDict(dict, path: pathKey, fallbackName: url.deletingPathExtension().lastPathComponent)
            }
        }
        if let dict = obj as? [String: Any] {
            // Nested rules array
            if let rules = dict["rules"] as? [[String: Any]] {
                return rules.compactMap {
                    eventFromPlistDict($0, path: pathKey, fallbackName: url.deletingPathExtension().lastPathComponent)
                }
            }
            if let event = eventFromPlistDict(
                dict,
                path: pathKey,
                fallbackName: url.deletingPathExtension().lastPathComponent
            ) {
                return [event]
            }
        }
        return []
    }

    private func eventFromPlistDict(
        _ dict: [String: Any],
        path: String,
        fallbackName: String
    ) -> EventEnvelope? {
        let name = emondName(from: dict, fallback: fallbackName)
        let command = command(from: dict)
        let enabled = enabledValue(from: dict)
        let eventTypes = eventTypes(from: dict)
        return makeEvent(RuleDetails(
            name: name,
            command: command.isEmpty ? name : command,
            enabled: enabled,
            eventTypes: eventTypes,
            path: path,
            extra: [:]
        ))
    }

    private func emondName(from dict: [String: Any], fallback: String) -> String {
        stringish(dict["name"]) ?? stringish(dict["Name"]) ?? stringish(dict["label"]) ?? fallback
    }

    private func command(from dict: [String: Any]) -> String {
        if let command = stringish(dict["command"]) ?? stringish(dict["Command"]) ?? stringish(dict["programArguments"]), !command.isEmpty {
            return command
        }
        if let actions = dict["actions"] as? [[String: Any]] {
            let commands = actions.compactMap { action -> String? in
                stringish(action["command"])
                    ?? stringish(action["Command"])
                    ?? (action["command"] as? [String])?.joined(separator: " ")
            }
            if !commands.isEmpty { return commands.joined(separator: " | ") }
        }
        return (dict["programArguments"] as? [String])?.joined(separator: " ") ?? ""
    }

    private func enabledValue(from dict: [String: Any]) -> String {
        (boolish(dict["enabled"]) ?? boolish(dict["Enabled"])).map { $0 ? "true" : "false" } ?? "true"
    }

    private func eventTypes(from dict: [String: Any]) -> String {
        (dict["eventTypes"] as? [String] ?? dict["EventTypes"] as? [String])?.joined(separator: ",") ?? ""
    }

    private func parseTextRule(at url: URL, text: String) -> [EventEnvelope] {
        let pathKey = ArtifactRoot.pathKey(url)
        let name = url.deletingPathExtension().lastPathComponent
        // First non-comment line as command summary
        var command = name
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = String(raw).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            command = line
            break
        }
        return [
            makeEvent(RuleDetails(
                name: name,
                command: command,
                enabled: "true",
                eventTypes: "",
                path: pathKey,
                extra: [:]
            )),
        ]
    }

    private func makeEvent(_ details: RuleDetails) -> EventEnvelope {
        var fields: [String: String] = [
            "persistence.kind": "emond",
            "persistence.label": details.name,
            "persistence.command": details.command,
            "persistence.path": details.path,
            "emond.rule_name": details.name,
            "emond.enabled": details.enabled,
            FieldTaxonomy.filePath: details.path,
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if !details.eventTypes.isEmpty {
            fields["emond.event_types"] = details.eventTypes
        }
        for (k, v) in details.extra where !v.isEmpty && fields[k] == nil {
            if k.hasPrefix("emond.") || k == "name" || k == "action" { continue }
            fields["emond.\(k)"] = v
        }
        let first = details.command.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init) ?? ""
        if first.hasPrefix("/") {
            fields[FieldTaxonomy.processPath] = first
            fields["persistence.program"] = first
        }

        var entities: [EntityID] = [
            EntityID(kind: .persistence, value: "emond|\(details.name)|\(details.command)"),
            .file(path: details.path),
        ]
        if first.hasPrefix("/") {
            entities.append(.file(path: first))
        }

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "persistence.item",
                label: "EMOND"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: entities,
                properties: fields,
                provenance: details.path,
                confidence: 0.94
            )
        )
    }

    private func isBinaryOrXMLPlist(_ url: URL) -> Bool {
        guard let data = try? Data(contentsOf: url, options: [.mappedIfSafe]), data.count >= 6 else {
            return false
        }
        if data.starts(with: Data("bplist".utf8)) { return true }
        if let head = String(data: data.prefix(64), encoding: .utf8),
           head.contains("<?xml") || head.contains("<plist") {
            return true
        }
        return false
    }
}
