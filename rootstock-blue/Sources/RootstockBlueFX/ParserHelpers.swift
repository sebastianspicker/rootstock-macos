import Foundation
import RootstockBlueCore

// MARK: - Scalar coercion (shared by FX parsers / IR posture)

/// Coerce JSON/plist scalar to `String`.
func stringish(_ value: Any?) -> String? {
    if let s = value as? String { return s }
    if let n = value as? NSNumber { return n.stringValue }
    return nil
}

/// Alias used by some inventory parsers.
func stringValue(_ any: Any?) -> String? {
    stringish(any)
}

/// Coerce JSON/plist scalar to `Bool`.
func boolish(_ value: Any?) -> Bool? {
    if let b = value as? Bool { return b }
    if let n = value as? NSNumber { return n.boolValue }
    if let s = value as? String {
        switch s.lowercased() {
        case "true", "yes", "1", "on", "enabled": return true
        case "false", "no", "0", "off", "disabled": return false
        default: return nil
        }
    }
    return nil
}

/// Parse ISO-8601 timestamps (with or without fractional seconds).
func parseDate(_ any: Any?) -> Date? {
    if let d = any as? Date { return d }
    if let s = any as? String {
        if let d = ISO8601DateFormatter().date(from: s) { return d }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.date(from: s)
    }
    if let n = any as? NSNumber {
        let v = n.doubleValue
        // Heuristic: ms vs seconds
        if v > 1e12 { return Date(timeIntervalSince1970: v / 1000.0) }
        if v > 1e9 { return Date(timeIntervalSince1970: v) }
    }
    return nil
}

/// Builds a parsed record's event at the record's own time. A record without a parseable
/// timestamp gets the epoch sentinel and `timestamp_missing=true`, never the parse time.
func recordEvent(at rawTime: Any?, _ make: (Date) -> EventEnvelope) -> EventEnvelope {
    guard let time = parseDate(rawTime) else {
        var event = make(Date(timeIntervalSince1970: 0))
        event.fields["timestamp_missing"] = "true"
        return event
    }
    return make(time)
}

/// Infer macOS username from a path containing `/Users/<name>/…`.
func inferUser(from path: String) -> String? {
    let parts = path.split(separator: "/").map(String.init)
    if let idx = parts.lastIndex(of: "Users"), idx + 1 < parts.count {
        let candidate = parts[idx + 1]
        if candidate != "Shared" && !candidate.hasPrefix(".") {
            return candidate
        }
    }
    return nil
}

/// Infer macOS username from a file URL path.
func inferUser(from url: URL) -> String? {
    inferUser(from: url.path)
}

/// Coerce JSON/plist array-ish values to `[String]`.
func stringArray(_ value: Any?) -> [String] {
    if let a = value as? [String] { return a }
    if let a = value as? [Any] {
        return a.compactMap { stringish($0) }
    }
    if let s = value as? String {
        return s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
    return []
}

// MARK: - JSON / plist I/O

/// Thread-safe collector for artifact read/parse failures; surfaced by `ForensicsEngine`.
public final class ArtifactFailureLog: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [String] = []
    private var recorded: Set<String> = []

    public init() {}

    /// Records a note once; parsers that read the same artifact do not inflate the count.
    public func record(_ note: String) {
        lock.lock()
        defer { lock.unlock() }
        guard recorded.insert(note).inserted else { return }
        entries.append(note)
    }

    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        entries.removeAll()
        recorded.removeAll()
    }

    public func snapshot() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return entries
    }
}

/// Shared loaders for forensic fixture JSON and property lists.
public enum ArtifactIO {
    /// Failures from artifacts that exist but cannot be read or parsed (missing files are not failures).
    public static let failures = ArtifactFailureLog()

    public static func data(contentsOf url: URL) -> Data? {
        do {
            return try Data(contentsOf: url)
        } catch {
            if (error as NSError).code != NSFileReadNoSuchFileError {
                failures.record("\(url.path): read failed: \(error.localizedDescription)")
            }
            return nil
        }
    }

    /// Runs a per-artifact parse; a thrown error is recorded in `failures` and yields no events
    /// instead of aborting the whole run.
    public static func attempt(_ url: URL, _ body: () throws -> [EventEnvelope]) -> [EventEnvelope] {
        do {
            return try body()
        } catch {
            failures.record("\(url.path): parse failed: \(error.localizedDescription)")
            return []
        }
    }

    public static func jsonObject(from data: Data) -> Any? {
        try? JSONSerialization.jsonObject(with: data)
    }

    /// Present but malformed JSON is recorded in `failures`; a missing file is not.
    public static func jsonObject(contentsOf url: URL) -> Any? {
        guard let data = data(contentsOf: url) else { return nil }
        guard let object = jsonObject(from: data) else {
            failures.record("\(url.path): parse failed: not valid JSON")
            return nil
        }
        return object
    }

    public static func jsonDict(from data: Data) -> [String: Any]? {
        jsonObject(from: data) as? [String: Any]
    }

    public static func jsonDict(contentsOf url: URL) -> [String: Any]? {
        jsonObject(contentsOf: url) as? [String: Any]
    }

    /// Deserialize any property-list root (dict, array, scalar).
    public static func plistObject(from data: Data) -> Any? {
        var format = PropertyListSerialization.PropertyListFormat.xml
        return try? PropertyListSerialization.propertyList(from: data, options: [], format: &format)
    }

    /// Present but malformed property lists are recorded in `failures`; a missing file is not.
    public static func plistObject(contentsOf url: URL) -> Any? {
        guard let data = data(contentsOf: url) else { return nil }
        guard let object = plistObject(from: data) else {
            failures.record("\(url.path): parse failed: not a valid property list")
            return nil
        }
        return object
    }

    public static func plistDict(from data: Data) -> [String: Any]? {
        plistObject(from: data) as? [String: Any]
    }

    public static func plistDict(contentsOf url: URL) -> [String: Any]? {
        plistObject(contentsOf: url) as? [String: Any]
    }

    /// Top-level array of dictionaries (InstallHistory, Safari downloads, Wi‑Fi, etc.).
    public static func plistArray(from data: Data) -> [[String: Any]]? {
        plistObject(from: data) as? [[String: Any]]
    }

    public static func plistArray(contentsOf url: URL) -> [[String: Any]]? {
        plistObject(contentsOf: url) as? [[String: Any]]
    }

    /// Dictionary entries from a plist root (array of dicts, or nested under keys).
    public static func plistDictionaryEntries(
        contentsOf url: URL,
        nestedKeys: [String] = [],
        identityKeys: [String] = []
    ) -> [[String: Any]] {
        guard let obj = plistObject(contentsOf: url) else { return [] }
        return dictionaryEntries(from: obj, nestedKeys: nestedKeys, identityKeys: identityKeys)
    }

    public static func plistDictionaryEntries(
        from data: Data,
        nestedKeys: [String] = [],
        identityKeys: [String] = []
    ) -> [[String: Any]] {
        guard let obj = plistObject(from: data) else { return [] }
        return dictionaryEntries(from: obj, nestedKeys: nestedKeys, identityKeys: identityKeys)
    }

    /// Prefer binary/XML plist; fall back to JSON object-as-dict.
    public static func jsonOrPlistDict(contentsOf url: URL) -> [String: Any]? {
        guard let data = data(contentsOf: url) else { return nil }
        if let dict = plistDict(from: data) { return dict }
        return jsonDict(from: data)
    }

    /// Prefer JSON dict; fall back to plist.
    public static func jsonOrPlistDictPreferJSON(contentsOf url: URL) -> [String: Any]? {
        guard let data = data(contentsOf: url) else { return nil }
        if let dict = jsonDict(from: data) { return dict }
        return plistDict(from: data)
    }

    /// Load a JSON file that is either a top-level array of dicts or a dict
    /// wrapping arrays under `nestedKeys`, or a single item when any of
    /// `identityKeys` is present.
    public static func jsonDictionaryEntries(
        contentsOf url: URL,
        nestedKeys: [String],
        identityKeys: [String] = []
    ) -> [[String: Any]] {
        guard let obj = jsonObject(contentsOf: url) else { return [] }
        return dictionaryEntries(from: obj, nestedKeys: nestedKeys, identityKeys: identityKeys)
    }

    public static func dictionaryEntries(
        from obj: Any,
        nestedKeys: [String],
        identityKeys: [String] = []
    ) -> [[String: Any]] {
        if let arr = obj as? [[String: Any]] {
            return arr
        }
        if let dict = obj as? [String: Any] {
            for key in nestedKeys {
                if let arr = dict[key] as? [[String: Any]] {
                    return arr
                }
            }
            if !identityKeys.isEmpty {
                for key in identityKeys where dict[key] != nil {
                    return [dict]
                }
            } else if nestedKeys.isEmpty {
                return [dict]
            }
        }
        return []
    }

    /// Parse JSONL (skip empty and `#` comment lines).
    ///
    /// Records end at LF or CRLF only: U+2028/U+2029 inside a JSON string are not record
    /// separators. Malformed records are skipped and counted in `failures`.
    public static func jsonlDictionaries(contentsOf url: URL) -> [[String: Any]] {
        guard let data = data(contentsOf: url) else { return [] }
        guard let text = String(data: data, encoding: .utf8) else {
            failures.record("\(url.path): parse failed: not UTF-8 text")
            return []
        }
        var rows: [[String: Any]] = []
        var malformed = 0
        for rawLine in text.split(whereSeparator: { $0 == "\n" || $0 == "\r\n" }) {
            let line = String(rawLine).trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard let obj = jsonDict(from: Data(line.utf8)) else {
                malformed += 1
                continue
            }
            rows.append(obj)
        }
        if malformed > 0 {
            failures.record("\(url.path): parse failed: \(malformed) malformed JSONL record(s) skipped")
        }
        return rows
    }
}

// MARK: - Path de-dupe

/// Track standardized path keys so multi-source discovery does not re-parse files.
public struct PathDeduper: Sendable {
    private var seen: Set<String> = []

    public init() {}

    /// Returns `true` the first time this path key is observed.
    @discardableResult
    public mutating func insert(_ url: URL) -> Bool {
        seen.insert(ArtifactRoot.pathKey(url)).inserted
    }

    public mutating func insert(pathKey key: String) -> Bool {
        seen.insert(key).inserted
    }

    public func contains(_ url: URL) -> Bool {
        seen.contains(ArtifactRoot.pathKey(url))
    }
}
