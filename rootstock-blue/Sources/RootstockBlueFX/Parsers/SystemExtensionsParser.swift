import Foundation
import RootstockBlueCore

/// System Extensions inventory (Network Extension, Endpoint Security, DriverKit, etc.).
///
/// Fixture-friendly: `Library/SystemExtensions/extensions.json`.
public struct SystemExtensionsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SYSTEMEXTENSIONS",
        tier: .tier1,
        description: "Installed system extensions (bundle id, state, team id)"
    )

    private struct SystemExtensionInfo {
        let bundleID: String
        let state: String
        let teamID: String
        let category: String
        let path: String
    }

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        var urls = enumeratedExtensionFiles(root: root, seen: &seen)
        appendExplicitExtensionFile(root: root, seen: &seen, to: &urls)
        return urls.flatMap { parseExtensionsFile(at: $0) }
    }

    private func enumeratedExtensionFiles(root: ArtifactRoot, seen: inout PathDeduper) -> [URL] {
        var urls: [URL] = []
        for url in root.enumerate(matching: isExtensionArtifact) where seen.insert(url) {
            ArtifactRoot.appendUnique(&urls, url)
        }
        return urls
    }

    private func isExtensionArtifact(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        let path = url.path
        if name == "extensions.json" && (path.contains("SystemExtensions") || path.contains("SystemPolicy")) {
            return true
        }
        let isConfigurationFile = name.hasSuffix(".json") || name.hasSuffix(".plist")
        return isConfigurationFile
            && (path.contains("/SystemExtensions/") || path.contains("SystemPolicyConfiguration"))
    }

    private func appendExplicitExtensionFile(root: ArtifactRoot, seen: inout PathDeduper, to urls: inout [URL]) {
        let paths = [
            "Library/SystemExtensions/extensions.json",
            "private/var/db/SystemPolicyConfiguration/extensions.json",
        ]
        guard let url = root.firstExisting(paths), seen.insert(url) else { return }
        ArtifactRoot.appendUnique(&urls, url)
    }

    private func parseExtensionsFile(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url) else { return [] }

        if let items = parseJSONItems(data) {
            return items.compactMap { makeEvent(item: $0, sourceURL: url) }
        }

        if let dict = ArtifactIO.plistDict(from: data),
           let items = extractItems(from: dict) {
            return items.compactMap { makeEvent(item: $0, sourceURL: url) }
        }

        return []
    }

    private func parseJSONItems(_ data: Data) -> [[String: Any]]? {
        guard let obj = ArtifactIO.jsonObject(from: data) else { return nil }
        return extractItems(from: obj)
    }

    private func extractItems(from obj: Any) -> [[String: Any]]? {
        if let arr = obj as? [[String: Any]] { return arr }
        if let arr = obj as? [Any] { return arr.compactMap { $0 as? [String: Any] } }
        if let dict = obj as? [String: Any] {
            if let items = dict["extensions"] as? [[String: Any]] { return items }
            if let items = dict["items"] as? [[String: Any]] { return items }
            if let items = dict["Extensions"] as? [[String: Any]] { return items }
        }
        return nil
    }

    private func makeEvent(item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let extensionInfo = SystemExtensionInfo(
            bundleID: stringValue(item["bundle_id"]) ?? stringValue(item["bundleId"])
                ?? stringValue(item["CFBundleIdentifier"]) ?? stringValue(item["identifier"]) ?? "",
            state: stringValue(item["state"]) ?? stringValue(item["State"]) ?? stringValue(item["status"]) ?? "",
            teamID: stringValue(item["team_id"]) ?? stringValue(item["teamId"])
                ?? stringValue(item["TeamIdentifier"]) ?? stringValue(item["team"]) ?? "",
            category: stringValue(item["category"]) ?? stringValue(item["Category"]) ?? stringValue(item["type"]) ?? "",
            path: stringValue(item["path"]) ?? stringValue(item["URL"]) ?? stringValue(item["url"]) ?? ""
        )
        guard !extensionInfo.bundleID.isEmpty || !extensionInfo.path.isEmpty else { return nil }

        let eventType = systemExtensionEventType(
            bundleID: extensionInfo.bundleID,
            category: extensionInfo.category
        )
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: eventType,
                label: "SYSTEMEXTENSIONS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: fileMTime(sourceURL),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: systemExtensionEntities(
                bundleID: extensionInfo.bundleID,
                teamID: extensionInfo.teamID,
                path: extensionInfo.path,
                sourceURL: sourceURL
            ),
                properties: systemExtensionFields(
                item: item,
                extensionInfo: extensionInfo,
                eventType: eventType,
                sourceURL: sourceURL
            ),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.93
            )
        )
    }

    private func systemExtensionEventType(bundleID: String, category: String) -> String {
        let isAppleDriver = category.lowercased().contains("driverkit")
            || bundleID.lowercased().hasPrefix("com.apple.")
        return isAppleDriver ? "host.system_extension" : "defense.system_extension"
    }

    private func systemExtensionFields(
        item: [String: Any],
        extensionInfo: SystemExtensionInfo,
        eventType: String,
        sourceURL: URL
    ) -> [String: String] {
        var fields: [String: String] = [
            "extension.bundle_id": extensionInfo.bundleID,
            "extension.state": extensionInfo.state,
            "extension.team_id": extensionInfo.teamID,
            "extension.category": extensionInfo.category,
            FieldTaxonomy.eventType: eventType,
            FieldTaxonomy.filePath: extensionInfo.path.isEmpty
                ? ArtifactRoot.pathKey(sourceURL)
                : extensionInfo.path,
        ]
        if !extensionInfo.path.isEmpty { fields["extension.path"] = extensionInfo.path }
        if let version = stringValue(item["version"]) ?? stringValue(item["CFBundleShortVersionString"]) {
            fields["extension.version"] = version
        }
        return fields
    }

    private func systemExtensionEntities(
        bundleID: String,
        teamID: String,
        path: String,
        sourceURL: URL
    ) -> [EntityID] {
        var entities: [EntityID] = [
            EntityID(kind: .host, value: "system_extension|\(bundleID.isEmpty ? path : bundleID)"),
            .file(path: ArtifactRoot.pathKey(sourceURL)),
        ]
        if !path.isEmpty { entities.append(.file(path: path)) }
        if !teamID.isEmpty { entities.append(EntityID(kind: .host, value: "team|\(teamID)")) }
        return entities
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
