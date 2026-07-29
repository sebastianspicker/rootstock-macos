/// Offline forensic parser: AutostartParser - fixture-backed IR events (no secret export).
import Foundation
import RootstockBlueCore
import RootstockMacFacts

public struct AutostartParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "AUTOSTART",
        tier: .tier1,
        description: "LaunchAgents, LaunchDaemons, and login-item style plists"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        let plists = root.enumerate { url in
            guard url.pathExtension == "plist" else { return false }
            let path = url.path
            return path.contains("LaunchAgents")
                || path.contains("LaunchDaemons")
                || path.contains("LaunchItems")
        }

        var events: [EventEnvelope] = []
        for plistURL in plists {
            if let event = parsePlist(at: plistURL) {
                events.append(event)
            }
        }
        return events
    }

    private struct PlistDetails {
        let kind: String
        let label: String
        let url: URL
        let program: String
        let arguments: [String]
        let runAtLoad: Bool
        let keepAlive: Bool
    }

    private func persistenceKind(for url: URL) -> String {
        if url.path.contains("LaunchDaemons") { return "launch_daemon" }
        if url.path.contains("LaunchAgents") { return "launch_agent" }
        return "launch_item"
    }

    private func persistenceFields(_ details: PlistDetails) -> [String: String] {
        var fields: [String: String] = [
            "persistence.kind": details.kind,
            "persistence.label": details.label,
            "persistence.path": details.url.path,
            "persistence.program": details.program,
            "persistence.program_arguments": details.arguments.joined(separator: " "),
            "persistence.run_at_load": details.runAtLoad ? "true" : "false",
            "persistence.keep_alive": details.keepAlive ? "true" : "false",
            "persistence.parser": "LaunchdPlistFacts",
            FieldTaxonomy.filePath: details.url.path,
            FieldTaxonomy.btmItemPath: details.url.path,
            FieldTaxonomy.btmItemType: details.kind,
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if !details.program.isEmpty { fields[FieldTaxonomy.processPath] = details.program }
        return fields
    }

    private func persistenceEntities(kind: String, label: String, url: URL, program: String) -> [EntityID] {
        var entities: [EntityID] = [
            EntityID(kind: .persistence, value: "\(kind)|\(label)"),
            .file(path: url.path),
        ]
        if !program.isEmpty { entities.append(.file(path: program)) }
        return entities
    }

    private func parsePlist(at url: URL) -> EventEnvelope? {
        guard let dict = ArtifactIO.plistDict(contentsOf: url) else { return nil }
        let summary = LaunchdPlistFacts.summarize(path: url.path, dict: dict)
        let details = PlistDetails(
            kind: persistenceKind(for: url),
            label: summary.label ?? url.deletingPathExtension().lastPathComponent,
            url: url,
            program: summary.program ?? summary.programArguments.first ?? "",
            arguments: summary.programArguments,
            runAtLoad: summary.runAtLoad,
            keepAlive: summary.keepAlive
        )
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        let mtime = (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "persistence.item",
                label: "AUTOSTART"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: mtime,
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: persistenceEntities(kind: details.kind, label: details.label, url: url, program: details.program),
                properties: persistenceFields(details),
                provenance: url.path,
                confidence: 0.98
            )
        )
    }
}
