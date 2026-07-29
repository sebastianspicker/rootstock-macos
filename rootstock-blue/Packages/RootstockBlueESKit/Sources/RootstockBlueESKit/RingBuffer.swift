import Foundation
import os
import RootstockBlueCore

/// Bounded in-memory queue for ES events. Drops are counted, never silent.
///
/// Concurrency: state is owned by `OSAllocatedUnfairLock`, so the buffer is
/// `Sendable` when `Element` is `Sendable` - no `@unchecked Sendable`.
public final class RingBuffer<Element: Sendable>: Sendable {
    private struct State: Sendable {
        var storage: [Element] = []
        var counters = LossCounters()
    }

    private let capacity: Int
    private let lock: OSAllocatedUnfairLock<State>

    public init(capacity: Int = 10_000) {
        self.capacity = max(1, capacity)
        self.lock = OSAllocatedUnfairLock(initialState: State())
    }

    @discardableResult
    public func enqueue(_ element: Element) -> Bool {
        lock.withLock { state in
            state.counters.recordReceived()
            if state.storage.count >= capacity {
                state.counters.recordDroppedBackpressure()
                return false
            }
            state.storage.append(element)
            state.counters.recordEnqueued()
            return true
        }
    }

    public func dequeueAll() -> [Element] {
        lock.withLock { state in
            let out = state.storage
            state.storage.removeAll(keepingCapacity: true)
            return out
        }
    }

    public func snapshotCounters() -> LossCounters {
        lock.withLock { state in
            state.counters
        }
    }
}
