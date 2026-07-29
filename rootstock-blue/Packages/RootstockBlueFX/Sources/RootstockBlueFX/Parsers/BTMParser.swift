import Foundation
import RootstockBlueCore

/// Background Task Management (BTM) items - macOS 13+ login/background items.
///
/// Type bit flags (mac_apt 2025 / Apple BTM research):
/// - 0x1  user item
/// - 0x2  app
/// - 0x4  login item
/// - 0x8  agent
/// - 0x10 daemon
/// - 0x20 developer
/// - 0x40 managed
/// - 0x80 curated
///
/// Disposition bit flags:
/// - 0x1 Enabled
/// - 0x2 Allowed
/// - 0x4 Hidden
/// - 0x8 Notified
public struct BTMParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "BTM",
        tier: .tier1,
        description: "Background Task Management (BTM) login/background items"
    )

    public init() {}

    private struct BTMDetails {
        let name: String
        let url: String
        let executablePath: String
        let type: Int
        let disposition: Int
        let developer: String
        let container: String
        let user: String
        let uid: String
        let filePath: String
        let index: Int
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        let urls = discoveredBTMURLs(root) + standardBTMURLs(root)
        return parseBTMURLs(urls)
    }

    private func discoveredBTMURLs(_ root: ArtifactRoot) -> [URL] {
        var urls: [URL] = []
        for found in root.enumerate(matching: isBTMFile) {
            ArtifactRoot.appendUnique(&urls, found)
        }
        return urls
    }

    private func isBTMFile(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        if name == "BackgroundItems.json" || name.hasSuffix(".btm.json") { return true }
        if name.hasPrefix("BackgroundItems-v") { return btmExtension(name) }
        return url.path.contains("backgroundtaskmanagement") && btmExtension(name)
    }

    private func btmExtension(_ name: String) -> Bool {
        name.hasSuffix(".btm") || name.hasSuffix(".btm.json") || name.hasSuffix(".json")
    }

    private func standardBTMURLs(_ root: ArtifactRoot) -> [URL] {
        var urls: [URL] = []
        for dirRel in [
            "private/var/db/com.apple.backgroundtaskmanagement",
            "var/db/com.apple.backgroundtaskmanagement",
        ] {
            let dir = root.file(dirRel)
            guard let items = try? FileManager.default.contentsOfDirectory(
                at: dir,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) else { continue }
            for item in items where isBTMFile(item) {
                ArtifactRoot.appendUnique(&urls, item)
            }
        }
        return urls
    }

    private func parseBTMURLs(_ urls: [URL]) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        var seenSources = PathDeduper()
        for url in urls {
            guard seenSources.insert(url) else { continue }
            events.append(contentsOf: parseBTMFile(at: url))
        }
        return events
    }

    private func parseBTMFile(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url) else { return [] }

        // Forensic intermediate JSON.
        if url.pathExtension == "json" || url.lastPathComponent.hasSuffix(".btm.json") {
            if let items = parseJSONItems(data) {
                return items.enumerated().compactMap { idx, item in
                    makeEvent(item: item, sourceURL: url, index: idx)
                }
            }
        }

        // Simplified plist with an `items` array (fixture-friendly).
        if let dict = ArtifactIO.plistDict(from: data),
           let items = extractItems(from: dict) {
            return items.enumerated().compactMap { idx, item in
                makeEvent(item: item, sourceURL: url, index: idx)
            }
        }

        // Raw .btm may also be JSON dumped by collection tools.
        if let items = parseJSONItems(data) {
            return items.enumerated().compactMap { idx, item in
                makeEvent(item: item, sourceURL: url, index: idx)
            }
        }

        return []
    }

    private func parseJSONItems(_ data: Data) -> [[String: Any]]? {
        guard let obj = ArtifactIO.jsonObject(from: data) else { return nil }
        return extractItems(from: obj)
    }

    private func extractItems(from obj: Any) -> [[String: Any]]? {
        if let dict = obj as? [String: Any] {
            if let items = dict["items"] as? [[String: Any]] {
                return items
            }
            if let items = dict["Items"] as? [[String: Any]] {
                return items
            }
            if let items = dict["items"] as? [Any] {
                return items.compactMap { $0 as? [String: Any] }
            }
        }
        if let arr = obj as? [[String: Any]] {
            return arr
        }
        if let arr = obj as? [Any] {
            return arr.compactMap { $0 as? [String: Any] }
        }
        return nil
    }

    private func makeEvent(item: [String: Any], sourceURL: URL, index: Int) -> EventEnvelope? {
        guard let details = btmDetails(item, sourceURL: sourceURL, index: index) else { return nil }
        let mtime = sourceModificationDate(sourceURL)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "persistence.btm_item",
                label: "BTM"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: mtime,
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: btmEntities(details),
                properties: btmFields(details),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.95
            )
        )
    }

    private func btmDetails(_ item: [String: Any], sourceURL: URL, index: Int) -> BTMDetails? {
        let name = stringValue(item["name"]) ?? stringValue(item["Name"]) ?? ""
        let url = firstString(item, keys: ["url", "URL", "item_url"])
        let executablePath = firstString(item, keys: ["executable_path", "executablePath", "ExecutablePath"])
        guard !name.isEmpty || !executablePath.isEmpty || !url.isEmpty else { return nil }
        return BTMDetails(
            name: name, url: url, executablePath: executablePath,
            type: intValue(item["type"] ?? item["Type"]) ?? 0,
            disposition: intValue(item["disposition"] ?? item["Disposition"]) ?? 0,
            developer: firstString(item, keys: ["developer", "Developer"]),
            container: firstString(item, keys: ["container", "Container"]),
            user: firstString(item, keys: ["user", "User"]),
            uid: firstString(item, keys: ["uid", "UID"]),
            filePath: btmFilePath(executable: executablePath, url: url, sourceURL: sourceURL), index: index
        )
    }

    private func firstString(_ item: [String: Any], keys: [String]) -> String {
        keys.lazy.compactMap { stringValue(item[$0]) }.first ?? ""
    }

    private func btmFilePath(executable: String, url: String, sourceURL: URL) -> String {
        if !executable.isEmpty { return executable }
        if url.hasPrefix("file://"), let fileURL = URL(string: url) { return fileURL.path }
        return url.isEmpty ? ArtifactRoot.pathKey(sourceURL) : url
    }

    private func sourceModificationDate(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }

    private func btmFields(_ details: BTMDetails) -> [String: String] {
        let typeLabel = typeLabels(details.type).joined(separator: ",")
        let dispositionLabels = dispositionLabels(details.disposition).joined(separator: ",")
        var fields: [String: String] = [
            "btm.name": details.name,
            "btm.type": String(details.type),
            "btm.type_label": typeLabel,
            "btm.disposition": String(details.disposition),
            "btm.disposition_labels": dispositionLabels,
            "btm.executable_path": details.executablePath,
            "btm.url": details.url,
            "btm.developer": details.developer,
            "btm.container": details.container,
            "btm.user": details.user,
            "btm.uid": details.uid,
            "btm.index": String(details.index),
            FieldTaxonomy.btmItemPath: details.filePath,
            FieldTaxonomy.btmItemType: typeLabel.isEmpty ? String(details.type) : typeLabel,
            FieldTaxonomy.filePath: details.filePath,
            FieldTaxonomy.eventType: "persistence.btm_item",
        ]
        if !details.user.isEmpty {
            fields[FieldTaxonomy.userName] = details.user
        }
        if !details.executablePath.isEmpty {
            fields[FieldTaxonomy.processPath] = details.executablePath
        }
        return fields
    }

    private func btmEntities(_ details: BTMDetails) -> [EntityID] {
        var entities: [EntityID] = [
            EntityID(kind: .persistence, value: "btm|\(details.name.isEmpty ? details.filePath : details.name)"),
            .file(path: details.filePath),
        ]
        if !details.user.isEmpty {
            entities.append(.user(name: details.user))
        } else if let uidNum = UInt32(details.uid), !details.uid.isEmpty {
            entities.append(.user(uid: uidNum))
        }
        return entities
    }

    /// Decode type bitfield into human labels (mac_apt 2025 research).
    private func typeLabels(_ raw: Int) -> [String] {
        bitLabels(raw, definitions: [
            (0x1, "user_item"), (0x2, "app"), (0x4, "login_item"), (0x8, "agent"),
            (0x10, "daemon"), (0x20, "developer"), (0x40, "managed"), (0x80, "curated"),
        ], fallbackPrefix: "type")
    }

    private func dispositionLabels(_ raw: Int) -> [String] {
        bitLabels(raw, definitions: [(0x1, "Enabled"), (0x2, "Allowed"), (0x4, "Hidden"), (0x8, "Notified")], fallbackPrefix: "disp")
    }

    private func bitLabels(_ raw: Int, definitions: [(Int, String)], fallbackPrefix: String) -> [String] {
        var labels: [String] = []
        for (bit, label) in definitions where raw & bit != 0 { labels.append(label) }
        if labels.isEmpty && raw != 0 { labels.append("\(fallbackPrefix)_\(raw)") }
        return labels
    }

    private func intValue(_ any: Any?) -> Int? {
        if let i = any as? Int { return i }
        if let n = any as? NSNumber { return n.intValue }
        if let s = any as? String, let i = Int(s) { return i }
        return nil
    }
}
