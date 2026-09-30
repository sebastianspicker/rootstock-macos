import Foundation
import RootstockBlueCore

/// Recent documents / MRU lists (plist or JSON) → timeline events with file entities.
public struct RecentItemsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "RECENTITEMS",
        tier: .tier2,
        description: "Recent documents and MRU file lists"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let candidates = ArtifactRoot(source: source).enumerate(matching: isRecentItemsFile)
        let plistDirectories = Set(candidates.filter { $0.pathExtension == "plist" }.map { ArtifactRoot.pathKey($0.deletingLastPathComponent()) })
        return candidates.flatMap { url in
            guard url.pathExtension != "json" || !plistDirectories.contains(ArtifactRoot.pathKey(url.deletingLastPathComponent())) else { return [EventEnvelope]() }
            return url.pathExtension == "json" ? parseJSON(url) : parsePlist(url)
        }
    }

    private func isRecentItemsFile(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        if ["RecentDocuments.plist", "RecentDocuments.json"].contains(name) { return true }
        if name.hasPrefix("com.apple.LSSharedFileList.RecentDocuments") { return true }
        return name.contains("Recent") && ["plist", "json"].contains(url.pathExtension) && url.path.contains("sharedfilelist")
    }

    private func parsePlist(_ url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url) else { return [] }
        // Prefer dict; fall back to raw property list for array top-level fixtures.
        if let dict = ArtifactIO.plistDict(from: data) {
            return events(from: dict, sourceURL: url)
        }
        guard let obj = ArtifactIO.plistObject(from: data) else { return [] }
        return events(from: obj, sourceURL: url)
    }

    private func parseJSON(_ url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        return events(from: obj, sourceURL: url)
    }

    private func events(from obj: Any, sourceURL: URL) -> [EventEnvelope] {
        let items = ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["items", "RecentDocuments"]
        )

        var out: [EventEnvelope] = []
        for (idx, item) in items.enumerated() {
            let name = stringValue(item["Name"]) ?? stringValue(item["name"]) ?? ""
            let fileURL = stringValue(item["URL"]) ?? stringValue(item["url"]) ?? ""
            guard !name.isEmpty || !fileURL.isEmpty else { continue }
            let path = fileURL.replacingOccurrences(of: "file://", with: "")
            var refs: [EntityID] = []
            if !path.isEmpty { refs.append(.file(path: path)) }
            out.append(
                EventEnvelope(
                    identity: EventEnvelope.Identity(
                        kind: "mru.document",
                        label: "RECENTITEMS"
                    ),
                    capture: EventEnvelope.Capture(
                        source: .parser,
                        eventTime: Date(timeIntervalSince1970: 0),
                        collectedAt: Date()
                    ),
                    payload: EventEnvelope.Payload(
                        entityRefs: refs,
                        properties: [
                        "mru.name": name,
                        "mru.url": fileURL,
                        "mru.path": path,
                        "mru.index": String(idx),
                        FieldTaxonomy.filePath: path,
                        FieldTaxonomy.eventType: "mru.document",
                        FieldTaxonomy.userName: inferUser(from: sourceURL) ?? "",
                    ],
                        provenance: ArtifactRoot.pathKey(sourceURL),
                        confidence: 0.88
                    )
                )
            )
        }
        return out
    }
}
