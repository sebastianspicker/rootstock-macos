import Foundation

/// Forensic time conversions used across parsers.
public enum Epochs {
    /// Mac absolute / CFAbsoluteTime: seconds since 2001-01-01 00:00:00 UTC.
    public static func dateFromMacAbsolute(_ raw: String) -> Date {
        guard let value = Double(raw), value != 0 else {
            return Date(timeIntervalSince1970: 0)
        }
        return dateFromMacAbsolute(value)
    }

    public static func dateFromMacAbsolute(_ value: Double) -> Date {
        if value <= 0 { return Date(timeIntervalSince1970: 0) }
        // Heuristic: values > 1e12 are ms; ~1e9 unix; smaller Mac absolute
        if value > 1_000_000_000_000 {
            return unixDate(value / 1000.0)
        }
        if value > 1_000_000_000 {
            return unixDate(value)
        }
        return unixDate(978_307_200 + value)
    }

    /// Chrome/WebKit: microseconds since 1601-01-01 00:00:00 UTC.
    public static func dateFromChromeMicroseconds(_ raw: String) -> Date {
        guard let value = Double(raw), value > 0 else {
            return Date(timeIntervalSince1970: 0)
        }
        return dateFromChromeMicroseconds(value)
    }

    public static func dateFromChromeMicroseconds(_ value: Double) -> Date {
        // Seconds between 1601-01-01 and 1970-01-01
        let windowsToUnixSeconds: Double = 11_644_473_600
        return unixDate((value / 1_000_000.0) - windowsToUnixSeconds)
    }

    /// Firefox / Gecko PRTime: microseconds since Unix epoch (1970-01-01 UTC).
    public static func dateFromFirefoxMicroseconds(_ raw: String) -> Date? {
        guard let value = Double(raw), value > 0 else { return nil }
        return dateFromFirefoxMicroseconds(value)
    }

    public static func dateFromFirefoxMicroseconds(_ value: Double) -> Date {
        // Values are typically > 1e14 for modern dates when stored as µs
        if value > 1_000_000_000_000 {
            return unixDate(value / 1_000_000.0)
        }
        if value > 1_000_000_000 {
            return unixDate(value)
        }
        return unixDate(value / 1_000_000.0)
    }

    /// A crafted value (NaN, infinity, year 290000) must not reach the case, whose
    /// ISO 8601 round trip cannot represent it; such values get the 1970 fallback.
    static func unixDate(_ seconds: Double) -> Date {
        guard seconds.isFinite, seconds >= 0, seconds < 4_102_444_800 else {  // before 2100-01-01
            return Date(timeIntervalSince1970: 0)
        }
        return Date(timeIntervalSince1970: seconds)
    }
}
