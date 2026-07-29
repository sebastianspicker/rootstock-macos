/// Offline forensic parser: FSEventsParser - fixture-backed IR events (no secret export).
import Foundation
import RootstockBlueCore

public struct FSEventsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "FSEVENTS",
        tier: .tier1,
        description: "FSEvents export JSONL under .fseventsd (alpha)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        let exports = root.enumerate {
            $0.path.contains(".fseventsd") && ($0.pathExtension == "jsonl" || $0.lastPathComponent == "export.jsonl")
        }
        var events: [EventEnvelope] = []
        for url in exports {
            events.append(contentsOf: try parseJSONL(url))
        }
        return events
    }

    private func parseJSONL(_ url: URL) throws -> [EventEnvelope] {
        var out: [EventEnvelope] = []
        for obj in ArtifactIO.jsonlDictionaries(contentsOf: url) {
            let path = stringValue(obj["path"]) ?? ""
            let flags = stringValue(obj["flags"]) ?? ""
            let eid = stringValue(obj["event_id"]) ?? String(describing: obj["event_id"] ?? "")
            out.append(
                EventEnvelope(
                    identity: EventEnvelope.Identity(
                        kind: "fsevents.entry",
                        label: "FSEVENTS"
                    ),
                    capture: EventEnvelope.Capture(
                        source: .parser,
                        eventTime: Date(timeIntervalSince1970: 0),
                        collectedAt: Date()
                    ),
                    payload: EventEnvelope.Payload(
                        entityRefs: path.isEmpty ? [] : [.file(path: path)],
                        properties: [
                        FieldTaxonomy.filePath: path,
                        "fsevents.flags": flags,
                        "fsevents.event_id": eid,
                        FieldTaxonomy.eventType: "fsevents.entry",
                    ],
                        provenance: url.path,
                        confidence: 0.7
                    )
                )
            )
        }
        return out
    }
}
