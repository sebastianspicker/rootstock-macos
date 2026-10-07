import Foundation
import os
import RootstockBlueCore

public protocol SyntheticEventClienting: AnyObject, Sendable {
    var counters: LossCounters { get }
    func start(profile: SyntheticEventProfile)
    func stop()
    func pollEvents() -> [EventEnvelope]
}

/// Synthetic fixture client for tests and CI. It has no entitlement or system-extension dependency.
///
/// Mutable session state is owned by `OSAllocatedUnfairLock`; the type is fully `Sendable`.
public final class SyntheticEventClient: SyntheticEventClienting, Sendable {
    private struct State: Sendable {
        var counters = LossCounters()
        var running = false
        var profile: SyntheticEventProfile?
    }

    private let state = OSAllocatedUnfairLock(initialState: State())
    private let buffer = RingBuffer<EventEnvelope>(capacity: 10_000)

    public init() {}

    public var counters: LossCounters {
        state.withLock { $0.counters }
    }

    public var running: Bool {
        state.withLock { $0.running }
    }

    public var profile: SyntheticEventProfile? {
        state.withLock { $0.profile }
    }

    public func start(profile: SyntheticEventProfile) {
        state.withLock { state in
            state.profile = profile
            state.running = true
        }
    }

    public func stop() {
        state.withLock { state in
            state.running = false
        }
    }

    /// Injected envelopes are always labelled `.synthetic`, and the profile's `MutePolicy` is applied
    /// (muted events are counted in `droppedMute`).
    public func inject(_ events: [EventEnvelope]) {
        state.withLock { state in
            let mute = state.profile.map { MutePolicy.merging($0) }
            for var event in events {
                event.source = .synthetic
                if let mute, Self.isMuted(event, by: mute) {
                    state.counters.recordReceived()
                    state.counters.recordDroppedMute()
                    continue
                }
                if buffer.enqueue(event) {
                    state.counters.recordReceived()
                    state.counters.recordEnqueued()
                    state.counters.recordMapped()
                } else {
                    state.counters.recordReceived()
                    state.counters.recordDroppedBackpressure()
                }
            }
        }
    }

    /// Maps synthetic raw fixture records into normalized event envelopes.
    public func injectSyntheticRaw(_ raw: [[String: String]]) {
        state.withLock { state in
            for item in raw {
                var mapCounters = LossCounters()
                if let env = SyntheticEventMapper.map(raw: item, counters: &mapCounters) {
                    if buffer.enqueue(env) {
                        state.counters.recordReceived()
                        state.counters.recordEnqueued()
                        state.counters.recordMapped()
                    } else {
                        state.counters.recordReceived()
                        state.counters.recordDroppedBackpressure()
                    }
                } else {
                    state.counters.recordReceived()
                    state.counters.recordMapFailure()
                }
            }
        }
    }

    private static func isMuted(_ event: EventEnvelope, by policy: MutePolicy) -> Bool {
        guard let path = event.fields[FieldTaxonomy.processPath] ?? event.fields[FieldTaxonomy.filePath] else {
            return false
        }
        return policy.shouldMute(path: path)
    }

    public func pollEvents() -> [EventEnvelope] {
        buffer.dequeueAll()
    }
}
