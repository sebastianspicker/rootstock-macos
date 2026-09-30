import Foundation
import RootstockBlueCore

/// Folder Actions / Automator-class event-triggered persistence (ATT&CK T1546).
///
/// Watches folder attach scripts/workflows under user and system Script libraries.
/// Not always-on like LaunchAgents - quiet in process lists until file events fire.
///
/// Significant improvement over directory listing: association inventory (watched
/// folder + script), risk tags (do shell script, Downloads watch, curl/tmp),
/// entity IDs, case custody, fixture CI.
public struct FolderActionsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "FOLDERACTIONS",
        tier: .tier1,
        description: "Folder Actions scripts/workflows and dispatcher associations"
    )

    public init() {}

    private struct ActionDetails {
        let name: String
        let scriptPath: String
        let watchedPath: String
        let enabled: String
        let user: String?
        let riskTags: [String]
        let rawRef: String
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        return collectKnownJSONActions(root, seen: &seen)
            + collectDiscoveredJSONActions(root, seen: &seen)
            + collectScriptActions(root, seen: &seen)
    }

    private func collectKnownJSONActions(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for rel in [
            "Library/Preferences/folder_actions.json",
            "Users/alice/Library/Workflows/folder_actions.json",
            "Users/alice/Library/Preferences/com.apple.FolderActionsDispatcher.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                let key = ArtifactRoot.pathKey(url)
                events.append(contentsOf: parseJSONInventory(json, rawRef: key, defaultUser: inferUser(from: key)))
            }
        }
        return events
    }

    private func collectDiscoveredJSONActions(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: isFolderActionJSON) {
            guard seen.insert(url) else { continue }
            let key = ArtifactRoot.pathKey(url)
            if let json = ArtifactIO.jsonObject(contentsOf: url) {
                events.append(contentsOf: parseJSONInventory(
                    json,
                    rawRef: key,
                    defaultUser: inferUser(from: key)
                ))
            }
        }
        return events
    }

    private func isFolderActionJSON(_ url: URL) -> Bool {
        guard !url.hasDirectoryPath else { return false }
        let name = url.lastPathComponent
        return name == "folder_actions.json"
            || name == "com.apple.FolderActionsDispatcher.json"
            || (url.path.contains("/FolderActions") && name.hasSuffix(".json"))
    }

    private func collectScriptActions(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: isFolderActionScript) {
            guard seen.insert(url) else { continue }
            let key = ArtifactRoot.pathKey(url)
            let name = url.deletingPathExtension().lastPathComponent
            let user = inferUser(from: key)
            let textSample = loadTextSample(url) ?? ""
            var risk = riskTags(forScriptPath: key, watched: "", scriptText: textSample)
            risk = Array(Set(risk)).sorted()
            events.append(makeEvent(ActionDetails(
                name: name, scriptPath: key, watchedPath: "", enabled: "true",
                user: user, riskTags: risk, rawRef: key
            )))
        }
        return events
    }

    private func isFolderActionScript(_ url: URL) -> Bool {
        guard !url.hasDirectoryPath, !url.lastPathComponent.hasPrefix(".") else { return false }
        let path = url.path
        if path.contains("Folder Action Scripts") || path.contains("/Workflows/Applications/Folder Actions/") {
            return true
        }
        return path.contains("/Workflows/")
            && supportedScriptExtension(url.lastPathComponent)
            && path.lowercased().contains("folder")
    }

    private func supportedScriptExtension(_ name: String) -> Bool {
        name.hasSuffix(".workflow") || name.hasSuffix(".scpt")
            || name.hasSuffix(".applescript") || name.hasSuffix(".sh")
    }

    private func parseJSONInventory(_ json: Any, rawRef: String, defaultUser: String?) -> [EventEnvelope] {
        actionItems(json).compactMap { item in
            actionDetails(item, rawRef: rawRef, defaultUser: defaultUser).map(makeEvent)
        }
    }

    private func actionItems(_ json: Any) -> [[String: Any]] {
        let items = ArtifactIO.dictionaryEntries(from: json, nestedKeys: ["actions", "folder_actions", "folderActions"])
        if !items.isEmpty { return items }
        if let dict = json as? [String: Any] { return [dict] }
        return json as? [[String: Any]] ?? []
    }

    private func actionDetails(_ item: [String: Any], rawRef: String, defaultUser: String?) -> ActionDetails? {
        let name = stringish(item["name"]) ?? stringish(item["label"]) ?? stringish(item["script"]) ?? "unnamed"
        let script = firstString(item, keys: ["script_path", "script", "path", "workflow"])
        let watched = firstString(item, keys: ["watched_path", "folder", "watched"])
        guard !script.isEmpty || !watched.isEmpty || !name.isEmpty else { return nil }
        let risk = combinedRiskTags(item, script: script, watched: watched)
        return ActionDetails(
            name: name,
            scriptPath: script.isEmpty ? rawRef : script,
            watchedPath: watched,
            enabled: boolish(item["enabled"]).map { $0 ? "true" : "false" } ?? "true",
            user: stringish(item["user"]) ?? defaultUser,
            riskTags: risk,
            rawRef: rawRef
        )
    }

    private func firstString(_ item: [String: Any], keys: [String]) -> String {
        for key in keys {
            if let value = stringish(item[key]) { return value }
        }
        return ""
    }

    private func combinedRiskTags(_ item: [String: Any], script: String, watched: String) -> [String] {
        var tags = stringish(item["risk_tags"])?
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) } ?? []
        let command = stringish(item["command"]) ?? stringish(item["body"]) ?? script
        tags.append(contentsOf: riskTags(forScriptPath: script, watched: watched, scriptText: command))
        return Array(Set(tags)).sorted()
    }

    private func makeEvent(_ details: ActionDetails) -> EventEnvelope {
        EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "persistence.item",
                label: "FOLDERACTIONS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: actionEntities(details),
                properties: actionFields(details),
                provenance: details.rawRef,
                confidence: 0.93
            )
        )
    }

    private func actionFields(_ details: ActionDetails) -> [String: String] {
        var fields: [String: String] = [
            "persistence.kind": "folder_action",
            "persistence.label": details.name,
            "persistence.command": details.scriptPath,
            "persistence.path": details.scriptPath,
            "folder_action.name": details.name,
            "folder_action.script_path": details.scriptPath,
            "folder_action.enabled": details.enabled,
            FieldTaxonomy.filePath: details.scriptPath,
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if !details.watchedPath.isEmpty {
            fields["folder_action.watched_path"] = details.watchedPath
            fields["persistence.watched_path"] = details.watchedPath
        }
        if let user = details.user, !user.isEmpty {
            fields[FieldTaxonomy.userName] = user
            fields["folder_action.scope"] = "user"
        } else {
            fields["folder_action.scope"] = "system"
        }
        if !details.riskTags.isEmpty {
            fields["persistence.risk_tags"] = details.riskTags.joined(separator: ",")
            fields["folder_action.risk_tags"] = details.riskTags.joined(separator: ",")
        }
        return fields
    }

    private func actionEntities(_ details: ActionDetails) -> [EntityID] {
        var entities: [EntityID] = [
            EntityID(kind: .persistence, value: "folder_action|\(details.user ?? "system")|\(details.name)|\(details.scriptPath)"),
            .file(path: details.scriptPath),
        ]
        if let user = details.user, !user.isEmpty {
            entities.append(.user(name: user))
        }
        if !details.watchedPath.isEmpty {
            entities.append(.file(path: details.watchedPath))
        }
        return entities
    }

    private func riskTags(forScriptPath script: String, watched: String, scriptText: String) -> [String] {
        let lower = (script + " " + scriptText).lowercased()
        let watchedLower = watched.lowercased()
        return shellRisk(lower) + networkRisk(lower) + temporaryRisk(lower) + payloadRisk(lower)
            + downloadsRisk(watchedLower) + desktopRisk(watchedLower) + suspiciousRisk(script, text: scriptText)
    }

    private func shellRisk(_ text: String) -> [String] {
        (text.contains("do shell script") || text.contains("doshellscript")) ? ["do_shell_script"] : []
    }

    private func networkRisk(_ text: String) -> [String] {
        (text.contains("curl") || text.contains("wget")) ? ["network_fetch"] : []
    }

    private func temporaryRisk(_ text: String) -> [String] {
        (text.contains("/tmp/") || text.contains("/var/tmp/")) ? ["tmp_payload"] : []
    }

    private func payloadRisk(_ text: String) -> [String] {
        text.contains("base64") ? ["base64_payload"] : []
    }

    private func downloadsRisk(_ watched: String) -> [String] {
        (watched.contains("/downloads") || watched.hasSuffix("downloads")) ? ["downloads_watch"] : []
    }

    private func desktopRisk(_ watched: String) -> [String] {
        (watched.contains("/desktop") || watched.hasSuffix("desktop")) ? ["desktop_watch"] : []
    }

    private func suspiciousRisk(_ script: String, text: String) -> [String] {
        (script.lowercased().contains("evil") || text.lowercased().contains("evil")) ? ["suspicious_name"] : []
    }

    private func loadTextSample(_ url: URL) -> String? {
        guard let data = try? Data(contentsOf: url), data.count < 256_000 else { return nil }
        if let text = String(data: data, encoding: .utf8) { return text }
        // Binary .scpt: extract printable ASCII for heuristics
        var printable = ""
        for b in data.prefix(8192) {
            if b >= 32 && b < 127 {
                printable.append(Character(UnicodeScalar(b)))
            } else {
                printable.append(" ")
            }
        }
        return printable
    }
}
