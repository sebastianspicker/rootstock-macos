import Foundation
import RootstockBlueCore
import RootstockBlueCase

public enum JSONLExporter {
    public static func exportEvents(_ events: [EventEnvelope], to url: URL) throws {
        try CaseOutputWriter.write(EventJSONL.encode(events), to: url)
    }

    /// Exports the verified case timeline with containment and no-clobber checks.
    @discardableResult
    public static func exportCase(_ package: CasePackage, to url: URL) throws -> Int {
        try package.verifyIntegrity()
        let events = try package.loadAllEvents()
        try CaseOutputWriter.write(EventJSONL.encode(events), from: package, to: url)
        return events.count
    }
}
