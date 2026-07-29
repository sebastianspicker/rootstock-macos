import Foundation
import RootstockBlueCore

/// Dual-emit helpers for osquery/Fleet compatibility - do not rebuild Fleet.
public enum OsqueryExport {
    public static func asOsqueryRow(_ event: EventEnvelope) -> [String: String] {
        var row = event.fields
        row["rootstock_blue_event_id"] = event.id.uuidString
        row["rootstock_blue_event_type"] = event.eventType
        row["rootstock_blue_source"] = event.source.rawValue
        row["rootstock_blue_source_plugin"] = event.sourcePlugin
        return row
    }
}
