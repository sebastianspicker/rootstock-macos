import Foundation
import RootstockBlueCore

/// Stub Elastic Common Schema field mapping.
public enum ECSMapper {
    public static func map(_ event: EventEnvelope) -> [String: String] {
        var out: [String: String] = [
            "@timestamp": ISO8601DateFormatter().string(from: event.eventTime),
            "event.module": "rootstock-blue",
            "event.dataset": event.sourcePlugin,
            "event.action": event.eventType,
        ]
        for (k, v) in event.fields {
            out[k] = v
        }
        return out
    }
}
