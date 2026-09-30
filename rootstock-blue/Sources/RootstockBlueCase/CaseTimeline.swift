import Foundation
import RootstockBlueCore

/// Storage-backed chronological view of the events verified from a case package.
public enum CaseTimeline {
    public static func merged(from package: CasePackage) throws -> [EventEnvelope] {
        try package.loadAllEvents().sorted { lhs, rhs in
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
