import Foundation
import RootstockBlueCore

/// Records synthetic fixture events into a sink (typically a `.rsbcase` package).
/// No live signed Endpoint Security implementation is included.
public struct SessionRecorder: Sendable {
    public let profile: SyntheticEventProfile

    public init(profile: SyntheticEventProfile = .builtin(.triage)) {
        self.profile = profile
    }

    /// Poll client and write all available events to the sink.
    @discardableResult
    public func flush(client: SyntheticEventClienting, into sink: EventSink) throws -> (written: Int, counters: LossCounters) {
        client.start(profile: profile)
        let events = client.pollEvents()
        if !events.isEmpty {
            try sink.append(
                events,
                custody: EventCustodyNote(
                    action: "record_flush",
                    detail: "Wrote \(events.count) synthetic events profile=\(profile.name.rawValue)"
                )
            )
        }
        return (events.count, client.counters)
    }

    /// Inject synthetic/raw fixture events and flush.
    @discardableResult
    public func recordInjected(
        raw: [[String: String]],
        client: SyntheticEventClient = SyntheticEventClient(),
        into sink: EventSink
    ) throws -> (written: Int, counters: LossCounters) {
        client.start(profile: profile)
        client.injectSyntheticRaw(raw)
        return try flush(client: client, into: sink)
    }

    @discardableResult
    public func recordEnvelopes(
        _ events: [EventEnvelope],
        client: SyntheticEventClient = SyntheticEventClient(),
        into sink: EventSink
    ) throws -> (written: Int, counters: LossCounters) {
        client.start(profile: profile)
        client.inject(events)
        return try flush(client: client, into: sink)
    }

    public static func loadEnvelopes(fromJSONL url: URL) throws -> [EventEnvelope] {
        try EventJSONL.decode(contentsOf: url)
    }
}
