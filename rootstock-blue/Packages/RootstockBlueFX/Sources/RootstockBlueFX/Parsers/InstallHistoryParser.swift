import Foundation
import RootstockBlueCore

/// Software install history from InstallHistory.plist (Library/Receipts).
/// Emits `software.install` envelopes with package/file entity refs for timeline/SQL.
public struct InstallHistoryParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "INSTALLHISTORY",
        tier: .tier2,
        description: "InstallHistory.plist software package installs"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []
        if let primary = root.firstExisting([
            "Library/Receipts/InstallHistory.plist",
            "private/var/db/receipts/InstallHistory.plist",
        ]) {
            ArtifactRoot.appendUnique(&urls, primary)
        }
        for found in root.enumerate(matching: { $0.lastPathComponent == "InstallHistory.plist" }) {
            ArtifactRoot.appendUnique(&urls, found)
        }

        var events: [EventEnvelope] = []
        for url in urls {
            events.append(contentsOf: parseHistory(at: url))
        }
        return events
    }

    private func parseHistory(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url) else { return [] }

        let entries: [[String: Any]]
        if let dict = ArtifactIO.plistDict(from: data),
           let arr = dict["InstallHistory"] as? [[String: Any]] {
            entries = arr
        } else if let arr = ArtifactIO.plistArray(from: data) {
            entries = arr
        } else {
            return []
        }

        return entries.enumerated().compactMap { installEvent(entry: $0.element, index: $0.offset, sourceURL: url) }
    }

    private func installEvent(entry: [String: Any], index: Int, sourceURL: URL) -> EventEnvelope? {
        let displayName = stringValue(entry["displayName"]) ?? stringValue(entry["DisplayName"]) ?? ""
        let packages = stringArray(entry["packageIdentifiers"] ?? entry["PackageIdentifiers"])
        guard !displayName.isEmpty || !packages.isEmpty else { return nil }
        let process = stringValue(entry["processName"]) ?? stringValue(entry["ProcessName"]) ?? ""
        let rawRef = ArtifactRoot.pathKey(sourceURL)
        var entities: [EntityID] = [EntityID(kind: .file, value: "pkg:\(packages.first ?? displayName)")]
        if !process.isEmpty { entities.append(EntityID(kind: .process, value: "name=\(process)")) }
        let fields = ["software.display_name": displayName, "software.version": stringValue(entry["displayVersion"]) ?? stringValue(entry["DisplayVersion"]) ?? "", "software.process_name": process, "software.content_type": stringValue(entry["contentType"]) ?? stringValue(entry["ContentType"]) ?? "", "software.package_identifiers": packages.joined(separator: ","), "software.install_index": String(index), "software.source_path": rawRef, FieldTaxonomy.processPath: process, FieldTaxonomy.eventType: "software.install"]
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "software.install",
                label: "INSTALLHISTORY"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(entry["date"] ?? entry["Date"]) ?? Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: entities,
                properties: fields,
                provenance: rawRef,
                confidence: 0.96
            )
        )
    }
}
