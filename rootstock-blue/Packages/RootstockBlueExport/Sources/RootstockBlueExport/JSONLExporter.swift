import Foundation
import RootstockBlueCore
import RootstockBlueCase

public enum JSONLExporter {
    public static func exportEvents(_ events: [EventEnvelope], to url: URL) throws {
        try EventJSONL.encode(events).write(to: url)
    }

    public static func exportCaseEvents(_ package: CasePackage, to url: URL) throws {
        // Intentionally ES stream only (historical API); net remains on package.loadAllEvents().
        var events: [EventEnvelope] = []
        if let files = try? FileManager.default.contentsOfDirectory(
            at: package.eventsESURL,
            includingPropertiesForKeys: nil
        ) {
            for file in files where file.pathExtension == "jsonl" {
                events.append(contentsOf: try EventJSONL.decode(contentsOf: file, skipInvalid: true))
            }
        }
        try exportEvents(events, to: url)
    }
}
