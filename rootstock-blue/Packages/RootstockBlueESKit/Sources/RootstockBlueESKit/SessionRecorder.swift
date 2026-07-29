import Foundation
import RootstockBlueCore

/// Records ES-shaped events into a sink (typically a `.rsbcase` package).
/// AUTH/block remains off; mock inject is the CI-reliable path.
public struct SessionRecorder: Sendable {
    public let profile: ESSubscriptionProfile

    public init(profile: ESSubscriptionProfile = .builtin(.ir)) {
        self.profile = profile
        precondition(!profile.authMode, "AUTH/block must remain off by default for alpha sessions")
    }

    /// Poll client and write all available events to the sink.
    @discardableResult
    public func flush(client: ESClienting, into sink: EventSink) throws -> (written: Int, counters: LossCounters) {
        try client.start(profile: profile)
        let events = client.pollEvents()
        for event in events {
            try sink.append(event)
        }
        if !events.isEmpty {
            try sink.noteCustody(
                action: "record_flush",
                detail: "Wrote \(events.count) ES events profile=\(profile.name.rawValue)"
            )
        }
        return (events.count, client.counters)
    }

    /// Inject synthetic/raw events via mock client and flush.
    @discardableResult
    public func recordInjected(
        raw: [[String: String]],
        client: MockESClient = MockESClient(),
        into sink: EventSink
    ) throws -> (written: Int, counters: LossCounters) {
        try client.start(profile: profile)
        client.injectRaw(raw)
        return try flush(client: client, into: sink)
    }

    @discardableResult
    public func recordEnvelopes(
        _ events: [EventEnvelope],
        client: MockESClient = MockESClient(),
        into sink: EventSink
    ) throws -> (written: Int, counters: LossCounters) {
        try client.start(profile: profile)
        client.inject(events)
        return try flush(client: client, into: sink)
    }

    public static func loadEnvelopes(fromJSONL url: URL) throws -> [EventEnvelope] {
        try EventJSONL.decode(contentsOf: url)
    }
}
