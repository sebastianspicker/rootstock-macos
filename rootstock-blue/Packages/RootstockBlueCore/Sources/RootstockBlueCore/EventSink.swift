import Foundation

/// Sink for session/record and collect writers.
public protocol EventSink: Sendable {
    func append(_ event: EventEnvelope) throws
    func noteCustody(action: String, detail: String) throws
}
