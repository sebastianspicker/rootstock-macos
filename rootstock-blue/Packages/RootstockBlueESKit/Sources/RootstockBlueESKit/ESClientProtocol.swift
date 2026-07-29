import Foundation
import os
import RootstockBlueCore

public protocol ESClienting: AnyObject, Sendable {
    var counters: LossCounters { get }
    func start(profile: ESSubscriptionProfile) throws
    func stop()
    func pollEvents() -> [EventEnvelope]
}

/// Mock ES client for tests and CI without FDA / ES entitlement.
///
/// Mutable session state is owned by `OSAllocatedUnfairLock`; the type is fully `Sendable`.
public final class MockESClient: ESClienting, Sendable {
    private struct State: Sendable {
        var counters = LossCounters()
        var running = false
        var profile: ESSubscriptionProfile?
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

    public var profile: ESSubscriptionProfile? {
        state.withLock { $0.profile }
    }

    public func start(profile: ESSubscriptionProfile) throws {
        try state.withLock { state in
            if profile.authMode {
                throw RootstockBlueError.notImplemented("AUTH/block mode is not implemented")
            }
            state.profile = profile
            state.running = true
        }
    }

    public func stop() {
        state.withLock { state in
            state.running = false
        }
    }

    public func inject(_ events: [EventEnvelope]) {
        state.withLock { state in
            for event in events {
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

    public func injectRaw(_ raw: [[String: String]]) {
        state.withLock { state in
            for item in raw {
                var mapCounters = LossCounters()
                if let env = ESEventMapper.map(raw: item, counters: &mapCounters) {
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

    public func pollEvents() -> [EventEnvelope] {
        buffer.dequeueAll()
    }
}

/// Endpoint Security factory that currently exposes only the mock client.
public enum LiveESClientFactory {
    /// Returns the mock client. Live access requires an entitlement, FDA, and root.
    public static func make(preferLive: Bool = false) -> any ESClienting {
        // Live EndpointSecurity requires a restricted entitlement.
        _ = preferLive
        return MockESClient()
    }
}
