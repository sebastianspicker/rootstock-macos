import Foundation

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

/// Shared loaders for forensic fixture JSON and property lists.
public enum ArtifactIO {
    public static func data(contentsOf url: URL) -> Data? {
        try? Data(contentsOf: url)
    }

    public static func jsonObject(from data: Data) -> Any? {
        try? JSONSerialization.jsonObject(with: data)
    }

    public static func jsonObject(contentsOf url: URL) -> Any? {
        guard let data = data(contentsOf: url) else { return nil }
        return jsonObject(from: data)
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

    public static func plistObject(contentsOf url: URL) -> Any? {
        guard let data = data(contentsOf: url) else { return nil }
        return plistObject(from: data)
    }

    public static func plistDict(from data: Data) -> [String: Any]? {
        plistObject(from: data) as? [String: Any]
    }

    public static func plistDict(contentsOf url: URL) -> [String: Any]? {
        guard let data = data(contentsOf: url) else { return nil }
        return plistDict(from: data)
    }

    /// Top-level array of dictionaries (InstallHistory, Safari downloads, Wi‑Fi, etc.).
    public static func plistArray(from data: Data) -> [[String: Any]]? {
        plistObject(from: data) as? [[String: Any]]
    }

    public static func plistArray(contentsOf url: URL) -> [[String: Any]]? {
        guard let data = data(contentsOf: url) else { return nil }
        return plistArray(from: data)
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
    public static func jsonlDictionaries(contentsOf url: URL) -> [[String: Any]] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        var rows: [[String: Any]] = []
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard let data = line.data(using: .utf8),
                  let obj = jsonDict(from: data)
            else { continue }
            rows.append(obj)
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
