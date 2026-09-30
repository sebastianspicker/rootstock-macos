import Foundation

/// Explicit telemetry loss metrics - never silent drops.
public struct LossCounters: Codable, Sendable, Equatable {
    public var received: UInt64
    public var enqueued: UInt64
    public var droppedBackpressure: UInt64
    public var droppedMute: UInt64
    public var mapped: UInt64
    public var mapFailures: UInt64

    public init(
        received: UInt64 = 0,
        enqueued: UInt64 = 0,
        droppedBackpressure: UInt64 = 0,
        droppedMute: UInt64 = 0,
        mapped: UInt64 = 0,
        mapFailures: UInt64 = 0
    ) {
        self.received = received
        self.enqueued = enqueued
        self.droppedBackpressure = droppedBackpressure
        self.droppedMute = droppedMute
        self.mapped = mapped
        self.mapFailures = mapFailures
    }

    public var totalDropped: UInt64 {
        droppedBackpressure + droppedMute + mapFailures
    }

    public mutating func recordReceived() { received += 1 }
    public mutating func recordEnqueued() { enqueued += 1 }
    public mutating func recordDroppedBackpressure() { droppedBackpressure += 1 }
    public mutating func recordDroppedMute() { droppedMute += 1 }
    public mutating func recordMapped() { mapped += 1 }
    public mutating func recordMapFailure() { mapFailures += 1 }
}
