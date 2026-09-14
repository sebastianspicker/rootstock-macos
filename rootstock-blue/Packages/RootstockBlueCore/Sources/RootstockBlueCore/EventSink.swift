import Foundation

/// Product-neutral custody annotation supplied with a logical event batch.
public struct EventCustodyNote: Sendable, Equatable {
    public var action: String
    public var detail: String

    public init(action: String, detail: String) {
        self.action = action
        self.detail = detail
    }
}

/// Sink for session/record and collect writers.
public protocol EventSink: Sendable {
    func append(_ event: EventEnvelope) throws
    func append(_ events: [EventEnvelope], custody: EventCustodyNote?) throws
    func noteCustody(action: String, detail: String) throws
}

public extension EventSink {
    /// Compatibility fallback for sinks that only implement single-record writes.
    /// Errors from event or custody callbacks are propagated unchanged.
    func append(_ events: [EventEnvelope], custody: EventCustodyNote? = nil) throws {
        for event in events {
            try append(event)
        }
        if let custody {
            try noteCustody(action: custody.action, detail: custody.detail)
        }
    }
}
