import Foundation

/// Whole-second UTC ISO 8601 text, identical to `JSONEncoder`'s `.iso8601` strategy.
///
/// Case JSONL records are encoded with that strategy, which truncates sub-second
/// precision. `ISO8601DateFormatter` rounds through milliseconds instead, so a date
/// late in a second would otherwise project one second later than its JSONL record.
public enum CaseTimestamp {
    public static func string(from date: Date) -> String {
        let wholeSeconds = date.timeIntervalSinceReferenceDate.rounded(.down)
        return ISO8601DateFormatter().string(from: Date(timeIntervalSinceReferenceDate: wholeSeconds))
    }
}
