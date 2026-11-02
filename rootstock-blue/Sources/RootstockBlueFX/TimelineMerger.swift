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
}
