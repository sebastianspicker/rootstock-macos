import Foundation
import RootstockBlueCore

/// Multi-source timeline merge with stable entity refs retained on each event.
public enum TimelineMerger {
    public static func merge(_ events: [EventEnvelope]) -> [EventEnvelope] {
        events.sorted { lhs, rhs in
            if lhs.eventTime != rhs.eventTime {
                return lhs.eventTime < rhs.eventTime
            }
            if lhs.source.rawValue != rhs.source.rawValue {
                return lhs.source.rawValue < rhs.source.rawValue
            }
            return lhs.id.uuidString < rhs.id.uuidString
        }
    }

    /// Deduplicate by id while preserving entity refs and chronological order.
    public static func mergeUnique(_ events: [EventEnvelope]) -> [EventEnvelope] {
        var seen = Set<UUID>()
        var unique: [EventEnvelope] = []
        for e in merge(events) where seen.insert(e.id).inserted {
                unique.append(e)
        }
        return unique
    }
}
