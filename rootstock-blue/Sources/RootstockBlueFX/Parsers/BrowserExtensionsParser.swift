import Foundation
import RootstockBlueCore

/// Browser extensions for Chrome (and Chromium) and Safari.
///
/// Accepts per-extension `manifest.json` trees or fixture-friendly
/// `extensions.json` / `Extensions.json` inventories.
public struct BrowserExtensionsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "BROWSER_EXTENSIONS",
        tier: .tier2,
        description: "Chrome and Safari browser extensions (manifest inventory)"
    )

    public init() {}

    private struct ExtensionDetails {
        let browser: String
        let id: String
        let name: String
        let version: String
        let permissions: String
        let user: String?
        let sourceURL: URL
        let extra: [String: Any]
    }

    private func extensionFields(_ details: ExtensionDetails) -> [String: String] {
        let broad = ["all_urls", "*://*/*", "<all_urls>", "://*/"].contains { details.permissions.lowercased().contains($0) }
        var fields: [String: String] = [
            "browser.name": details.browser,
            "extension.id": details.id,
            "extension.name": details.name,
            "extension.version": details.version,
            "extension.permissions": details.permissions,
            "extension.broad_permissions": broad ? "true" : "false",
            FieldTaxonomy.eventType: "browser.extension",
            FieldTaxonomy.filePath: ArtifactRoot.pathKey(details.sourceURL),
        ]
        if let user = details.user, !user.isEmpty { fields[FieldTaxonomy.userName] = user }
        if let description = stringValue(details.extra["description"]) { fields["extension.description"] = description }
        if let enabled = details.extra["enabled"] { fields["extension.enabled"] = boolString(enabled) }
        return fields
    }

    private func extensionInventoryItems(_ object: Any, keys: [String]) -> [[String: Any]] {
        if let items = object as? [[String: Any]] { return items }
        guard let dictionary = object as? [String: Any] else { return [] }
        if let items = keys.lazy.compactMap({ dictionary[$0] as? [[String: Any]] }).first { return items }
        return dictionary.compactMap { key, value in
            guard var item = value as? [String: Any] else { return nil }
            if item["id"] == nil { item["id"] = key }
            return item
        }
    }

    private func isChromeExtensionFile(_ url: URL) -> Bool {
        let path = url.path
        let chromiumBrowser = ["Chrome", "Chromium", "Edge", "Brave", "Google"].contains { path.contains($0) }
        if url.lastPathComponent == "extensions.json" { return chromiumBrowser }
        return url.lastPathComponent == "manifest.json" && path.contains("/Extensions/") && chromiumBrowser
    }

    private func isSafariExtensionFile(_ url: URL) -> Bool {
        guard url.path.contains("/Safari/") else { return false }
        return ["Extensions.json", "extensions.json", "manifest.json"].contains(url.lastPathComponent)
            && (url.lastPathComponent != "manifest.json" || url.path.contains("/Extensions/"))
    }

    private func collectChromeExtensions(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: isChromeExtensionFile) {
            guard seen.insert(url) else { continue }
            events.append(contentsOf: url.lastPathComponent == "extensions.json" ? parseChromeInventory(at: url) : parseChromeManifest(at: url))
        }
        return events
    }

    private func collectSafariExtensions(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: isSafariExtensionFile) {
            guard seen.insert(url) else { continue }
            events.append(contentsOf: url.lastPathComponent.lowercased().contains("extensions.json") ? parseSafariInventory(at: url) : parseSafariManifest(at: url))
        }
        return events
    }

    private func collectFixtureExtensions(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        let paths = ["Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/extensions.json", "Users/alice/Library/Safari/Extensions/Extensions.json"]
        var events: [EventEnvelope] = []
        for path in paths {
            guard let url = root.firstExisting([path]), seen.insert(url) else { continue }
            events.append(contentsOf: url.path.contains("Safari") ? parseSafariInventory(at: url) : parseChromeInventory(at: url))
        }
        return events
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        return collectChromeExtensions(root: root, seen: &seen)
            + collectSafariExtensions(root: root, seen: &seen)
            + collectFixtureExtensions(root: root, seen: &seen)
    }

    // MARK: - Chrome

    private func parseChromeInventory(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        let items = extensionInventoryItems(obj, keys: ["extensions", "items"])
        return items.compactMap { item in
            makeExtensionEvent(ExtensionDetails(
                browser: "chrome",
                id: stringValue(item["id"]) ?? stringValue(item["extension_id"]) ?? "",
                name: stringValue(item["name"]) ?? stringValue(item["short_name"]) ?? "",
                version: stringValue(item["version"]) ?? "",
                permissions: permissionsString(item["permissions"] ?? item["host_permissions"]),
                user: inferUser(from: url),
                sourceURL: url,
                extra: item
            ))
        }
    }

    private func parseChromeManifest(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonDict(contentsOf: url) else { return [] }
        let parts = url.pathComponents
        let id = parts.indices.contains(where: { parts[$0] == "Extensions" && $0 + 1 < parts.count })
            ? parts[parts.lastIndex(of: "Extensions")! + 1] : ""
        return [makeExtensionEvent(ExtensionDetails(
            browser: "chrome",
            id: id,
            name: localizedName(obj["name"]) ?? stringValue(obj["name"]) ?? "",
            version: stringValue(obj["version"]) ?? "",
            permissions: permissionsString(obj["permissions"]),
            user: inferUser(from: url),
            sourceURL: url,
            extra: obj
        ))].compactMap { $0 }
    }

    // MARK: - Safari

    private func parseSafariInventory(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        return extensionInventoryItems(obj, keys: ["extensions", "Installed Extensions"]).compactMap { item in
            makeExtensionEvent(ExtensionDetails(
                browser: "safari",
                id: stringValue(item["id"]) ?? stringValue(item["bundle_id"]) ?? stringValue(item["Bundle Identifier"]) ?? "",
                name: stringValue(item["name"]) ?? stringValue(item["Display Name"]) ?? "",
                version: stringValue(item["version"]) ?? stringValue(item["Version"]) ?? "",
                permissions: permissionsString(item["permissions"] ?? item["Permissions"]),
                user: inferUser(from: url),
                sourceURL: url,
                extra: item
            ))
        }
    }

    private func parseSafariManifest(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonDict(contentsOf: url) else { return [] }
        return [makeExtensionEvent(ExtensionDetails(
            browser: "safari",
            id: stringValue(obj["bundle_id"]) ?? stringValue(obj["id"]) ?? url.deletingLastPathComponent().lastPathComponent,
            name: localizedName(obj["name"]) ?? stringValue(obj["name"]) ?? "",
            version: stringValue(obj["version"]) ?? "",
            permissions: permissionsString(obj["permissions"]),
            user: inferUser(from: url),
            sourceURL: url,
            extra: obj
        ))].compactMap { $0 }
    }

    // MARK: - shared

    private func makeExtensionEvent(_ details: ExtensionDetails) -> EventEnvelope? {
        guard !details.id.isEmpty || !details.name.isEmpty else { return nil }
        var entities: [EntityID] = [
            EntityID(kind: .host, value: "browser_extension|\(details.browser)|\(details.id.isEmpty ? details.name : details.id)"),
            .file(path: ArtifactRoot.pathKey(details.sourceURL)),
        ]
        if let user = details.user, !user.isEmpty { entities.append(.user(name: user)) }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "browser.extension",
                label: "BROWSER_EXTENSIONS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: fileMTime(details.sourceURL),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: entities,
                properties: extensionFields(details),
                provenance: ArtifactRoot.pathKey(details.sourceURL),
                confidence: 0.95
            )
        )
    }

    private func permissionsString(_ any: Any?) -> String {
        if let s = any as? String { return s }
        if let a = any as? [String] { return a.joined(separator: ",") }
        if let a = any as? [Any] {
            return a.compactMap { $0 as? String }.joined(separator: ",")
        }
        return ""
    }

    /// Chrome manifests often use `__MSG_extName__` - keep as-is unless a simple string.
    private func localizedName(_ any: Any?) -> String? {
        stringValue(any)
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
