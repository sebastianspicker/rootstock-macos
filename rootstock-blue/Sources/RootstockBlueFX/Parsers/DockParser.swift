import Foundation
import RootstockBlueCore

/// Dock persistent/recent apps and folders from com.apple.dock.plist.
/// Emits dock.item / mru.app events with file entity refs for case timeline merge.
public struct DockParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "DOCK",
        tier: .tier2,
        description: "Dock persistent-apps, recent-apps, and folders"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        let plists = root.enumerate { url in
            url.lastPathComponent == "com.apple.dock.plist"
        }
        var events: [EventEnvelope] = []
        for url in plists {
            events.append(contentsOf: parseDock(at: url))
        }
        return events
    }

    private func parseDock(at url: URL) -> [EventEnvelope] {
        guard let dict = ArtifactIO.plistDict(contentsOf: url) else { return [] }

        let user = inferUser(from: url)
        var events: [EventEnvelope] = []
        events.append(contentsOf: tiles(
            dict["persistent-apps"] as? [Any] ?? [],
            kind: "persistent_app",
            eventType: "dock.item",
            sourceURL: url,
            user: user
        ))
        events.append(contentsOf: tiles(
            dict["recent-apps"] as? [Any] ?? [],
            kind: "recent_app",
            eventType: "mru.app",
            sourceURL: url,
            user: user
        ))
        events.append(contentsOf: tiles(
            dict["persistent-others"] as? [Any] ?? [],
            kind: "persistent_other",
            eventType: "dock.item",
            sourceURL: url,
            user: user
        ))
        return events
    }

    private func tiles(
        _ items: [Any],
        kind: String,
        eventType: String,
        sourceURL: URL,
        user: String?
    ) -> [EventEnvelope] {
        let context = TileContext(kind: kind, eventType: eventType, sourceURL: sourceURL, user: user)
        return items.enumerated().compactMap { tileEvent(item: $0.element, index: $0.offset, context: context) }
    }

    private struct TileContext {
        let kind: String
        let eventType: String
        let sourceURL: URL
        let user: String?
    }

    private struct DockTile {
        let label: String
        let bundle: String
        let path: String
    }

    private func tileEvent(item: Any, index: Int, context: TileContext) -> EventEnvelope? {
        guard let tile = item as? [String: Any], let details = dockTile(from: tile) else { return nil }
        return dockTileEnvelope(details: details, index: index, context: context)
    }

    private func dockTile(from tile: [String: Any]) -> DockTile? {
        let data = tile["tile-data"] as? [String: Any] ?? tile
        let label = stringValue(data["file-label"]) ?? stringValue(data["bundle-identifier"]) ?? ""
        let bundle = stringValue(data["bundle-identifier"]) ?? ""
        let path = extractPath(from: data)
        guard !label.isEmpty || !path.isEmpty || !bundle.isEmpty else { return nil }
        return DockTile(label: label, bundle: bundle, path: path)
    }

    private func dockTileEnvelope(details: DockTile, index: Int, context: TileContext) -> EventEnvelope {
        EventEnvelope(identity: EventEnvelope.Identity(kind: context.eventType, label: "DOCK"), capture: EventEnvelope.Capture(source: .parser, eventTime: Date(timeIntervalSince1970: 0), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: dockEntities(path: details.path, user: context.user), properties: dockFields(details: details, index: index, context: context), provenance: ArtifactRoot.pathKey(context.sourceURL), confidence: 0.9))
    }

    private func dockEntities(path: String, user: String?) -> [EntityID] {
        var entities: [EntityID] = []
        if !path.isEmpty { entities.append(.file(path: path)) }
        if let user, !user.isEmpty { entities.append(.user(name: user)) }
        return entities
    }

    private func dockFields(details: DockTile, index: Int, context: TileContext) -> [String: String] {
        var fields = ["dock.kind": context.kind, "dock.label": details.label, "dock.bundle_id": details.bundle, "dock.path": details.path, "dock.index": String(index), "dock.plist_path": ArtifactRoot.pathKey(context.sourceURL), FieldTaxonomy.filePath: details.path, FieldTaxonomy.eventType: context.eventType, FieldTaxonomy.userName: context.user ?? ""]
        if !details.bundle.isEmpty { fields["app.bundle_id"] = details.bundle }
        return fields
    }

    private func extractPath(from tileData: [String: Any]) -> String {
        if let fileData = tileData["file-data"] as? [String: Any] {
            if let s = stringValue(fileData["_CFURLString"]) {
                return normalizeFileURL(s)
            }
            if let s = stringValue(fileData["URL"]) {
                return normalizeFileURL(s)
            }
        }
        if let s = stringValue(tileData["file-path"]) {
            return normalizeFileURL(s)
        }
        if let s = stringValue(tileData["path"]) {
            return normalizeFileURL(s)
        }
        return ""
    }

    private func normalizeFileURL(_ s: String) -> String {
        var t = s
        if t.hasPrefix("file://") {
            t = String(t.dropFirst("file://".count))
            // Percent-decode lightly
            t = t.removingPercentEncoding ?? t
        }
        // Drop trailing slash for apps if desired - keep as-is for dirs
        return t
    }

}
