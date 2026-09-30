import Foundation
import RootstockBlueCore

/// Login Items from sharedfilelist JSON exports and BTM agent support paths.
///
/// Fixture-friendly: `com.apple.LSSharedFileList.LoginItems.json` as an array of
/// `{name, path, hidden}`.
public struct LoginItemsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "LOGINITEMS",
        tier: .tier1,
        description: "User Login Items (sharedfilelist / backgroundtaskmanagementagent)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []
        var seen = PathDeduper()

        for found in root.enumerate(matching: loginItemPathMatch) {
            if !seen.insert(found) { continue }
            ArtifactRoot.appendUnique(&urls, found)
        }

        // Explicit fixture path
        if let explicit = root.firstExisting([
            "Users/alice/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.LoginItems.json",
        ]) {
            if seen.insert(explicit) {
                ArtifactRoot.appendUnique(&urls, explicit)
            }
        }

        var events: [EventEnvelope] = []
        for url in urls {
            events.append(contentsOf: parseLoginItemsFile(at: url))
        }
        return events
    }

    private func loginItemPathMatch(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        let path = url.path
        if name == "com.apple.LSSharedFileList.LoginItems.json"
            || name == "com.apple.LSSharedFileList.LoginItems.sfl2.json"
            || name == "LoginItems.json" { return true }
        if path.contains("sharedfilelist") && name.lowercased().contains("loginitem") { return true }
        return isBackgroundTaskPath(path: path, name: name)
    }

    private func isBackgroundTaskPath(path: String, name: String) -> Bool {
        guard path.contains("backgroundtaskmanagementagent") else { return false }
        return name.hasSuffix(".json") || name.hasSuffix(".plist") || name.hasSuffix(".btm")
    }

    private func parseLoginItemsFile(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url) else { return [] }
        let user = inferUser(from: url)

        // JSON first (fixtures)
        if url.pathExtension == "json" || url.lastPathComponent.hasSuffix(".json") {
            if let items = parseJSONItems(data) {
                return items.enumerated().compactMap { idx, item in
                    makeEvent(item: item, sourceURL: url, user: user, index: idx)
                }
            }
        }

        // Plist (rare simplified export)
        if let dict = ArtifactIO.plistDict(from: data),
           let items = extractItems(from: dict) {
            return items.enumerated().compactMap { idx, item in
                makeEvent(item: item, sourceURL: url, user: user, index: idx)
            }
        }

        // Last-chance JSON without extension
        if let items = parseJSONItems(data) {
            return items.enumerated().compactMap { idx, item in
                makeEvent(item: item, sourceURL: url, user: user, index: idx)
            }
        }

        return []
    }

    private func parseJSONItems(_ data: Data) -> [[String: Any]]? {
        guard let obj = ArtifactIO.jsonObject(from: data) else { return nil }
        return extractItems(from: obj)
    }

    private func extractItems(from obj: Any) -> [[String: Any]]? {
        if let arr = obj as? [[String: Any]] {
            return arr
        }
        if let arr = obj as? [Any] {
            return arr.compactMap { $0 as? [String: Any] }
        }
        if let dict = obj as? [String: Any] {
            if let items = dict["items"] as? [[String: Any]] { return items }
            if let items = dict["Items"] as? [[String: Any]] { return items }
            if let items = dict["login_items"] as? [[String: Any]] { return items }
        }
        return nil
    }

    private func makeEvent(item: [String: Any], sourceURL: URL, user: String?, index: Int) -> EventEnvelope? {
        let name = stringValue(item["name"]) ?? stringValue(item["Name"]) ?? stringValue(item["label"]) ?? ""
        let path = stringValue(item["path"])
            ?? stringValue(item["Path"])
            ?? stringValue(item["URL"])
            ?? stringValue(item["url"])
            ?? ""
        let hidden = boolString(item["hidden"] ?? item["Hidden"])

        guard !name.isEmpty || !path.isEmpty else { return nil }

        var fields: [String: String] = [
            "persistence.kind": "login_item",
            "persistence.label": name,
            "persistence.path": path.isEmpty ? ArtifactRoot.pathKey(sourceURL) : path,
            "persistence.hidden": hidden,
            "persistence.index": String(index),
            FieldTaxonomy.filePath: path.isEmpty ? ArtifactRoot.pathKey(sourceURL) : path,
            FieldTaxonomy.btmItemPath: path.isEmpty ? ArtifactRoot.pathKey(sourceURL) : path,
            FieldTaxonomy.btmItemType: "login_item",
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if let user, !user.isEmpty {
            fields[FieldTaxonomy.userName] = user
        }
        if !path.isEmpty {
            fields[FieldTaxonomy.processPath] = path
            fields["persistence.program"] = path
        }

        let entities = makeEntities(name: name, path: path, sourceURL: sourceURL, user: user)

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "persistence.item",
                label: "LOGINITEMS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: fileMTime(sourceURL),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: entities,
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.94
            )
        )
    }

    private func makeEntities(name: String, path: String, sourceURL: URL, user: String?) -> [EntityID] {
        var entities: [EntityID] = [.init(kind: .persistence, value: "login_item|\(name.isEmpty ? path : name)")]
        if !path.isEmpty { entities.append(.file(path: path)) }
        entities.append(.file(path: ArtifactRoot.pathKey(sourceURL)))
        if let user, !user.isEmpty { entities.append(.user(name: user)) }
        return entities
    }

    private func boolString(_ any: Any?) -> String {
        if let b = boolish(any) { return b ? "true" : "false" }
        return "false"
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
