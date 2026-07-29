import Foundation
import RootstockBlueCore

/// Integrate with Santa - do not reimplement the allowlist decision engine.
/// Pure EventEnvelope production (no Case dependency); CLI/case layer writes results.
public enum SantaBridge {
    public static let status = "integrate_only"

    /// Ingest Santa decision logs (JSONL preferred; also accepts single JSON objects per line).
    /// Fixture shape:
    /// `{"decision":"DENY","path":"/tmp/evil_payload","sha256":"abc","reason":"BLOCKLIST","timestamp":"2026-01-15T12:00:00Z"}`
    public static func eventsFromSantaLog(at url: URL) throws -> [EventEnvelope] {
        let text = try santaLogText(at: url)
        let dates = SantaDateParsers()
        let events = try text.components(separatedBy: .newlines).enumerated().compactMap {
            try santaEvent(rawLine: $0.element, lineNumber: $0.offset + 1, url: url, dates: dates)
        }
        guard !events.isEmpty else { throw RootstockBlueError.io("No Santa decisions parsed from \(url.path)") }
        return events
    }

    private struct SantaDateParsers {
        let fractional = ISO8601DateFormatter()
        let basic = ISO8601DateFormatter()

        init() {
            fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            basic.formatOptions = [.withInternetDateTime]
        }
    }

    private static func santaLogText(at url: URL) throws -> String {
        let data = try Data(contentsOf: url)
        guard let text = String(data: data, encoding: .utf8) else { throw RootstockBlueError.io("Santa log is not UTF-8: \(url.path)") }
        return text
    }

    private static func santaEvent(rawLine: String, lineNumber: Int, url: URL, dates: SantaDateParsers) throws -> EventEnvelope? {
        let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !line.isEmpty, !line.hasPrefix("#") else { return nil }
        let reference = "\(url.path)#L\(lineNumber)"
        if line.hasPrefix("{") { return try eventFromJSONLine(line, lineNumber: lineNumber, dates: dates, rawRef: reference) }
        return eventFromCSVLine(line, dates: dates, rawRef: reference)
    }

    private static func eventFromJSONLine(_ line: String, lineNumber: Int, dates: SantaDateParsers, rawRef: String) throws -> EventEnvelope? {
        guard let data = line.data(using: .utf8), let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw RootstockBlueError.io("Santa log JSON parse failed at line \(lineNumber)")
        }
        return eventFromDecisionObject(object, iso: dates.fractional, isoBasic: dates.basic, rawRef: rawRef)
    }

    private static func eventFromCSVLine(_ line: String, dates: SantaDateParsers, rawRef: String) -> EventEnvelope? {
        let columns = line.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard columns.count >= 2 else { return nil }
        var object: [String: Any] = ["decision": columns[0], "path": columns[1]]
        if columns.count > 2 { object["sha256"] = columns[2] }
        if columns.count > 3 { object["reason"] = columns[3] }
        if columns.count > 4 { object["timestamp"] = columns[4] }
        return eventFromDecisionObject(object, iso: dates.fractional, isoBasic: dates.basic, rawRef: rawRef)
    }

    /// Suggest a manual Santa rule snippet from an event (review required).
    public static func suggestRule(from event: EventEnvelope) -> String {
        let path = event.fields[FieldTaxonomy.processPath]
            ?? event.fields[FieldTaxonomy.filePath]
            ?? "unknown"
        let team = event.fields[FieldTaxonomy.processTeamID] ?? ""
        let sha = event.fields["santa.sha256"] ?? event.fields["file.sha256"] ?? ""
        return """
        # Suggested Santa rule (manual review)
        # path: \(path)
        # teamid: \(team)
        # sha256: \(sha)
        """
    }

    // MARK: - Private

    private static func eventFromDecisionObject(
        _ obj: [String: Any],
        iso: ISO8601DateFormatter,
        isoBasic: ISO8601DateFormatter,
        rawRef: String
    ) -> EventEnvelope? {
        let decision = stringField(obj, keys: ["decision", "Decision", "action"]) ?? "UNKNOWN"
        let path = stringField(obj, keys: ["path", "file_path", "executable", "filePath"]) ?? ""
        let sha256 = stringField(obj, keys: ["sha256", "SHA256", "hash"]) ?? ""
        let reason = stringField(obj, keys: ["reason", "Reason", "rule_type"]) ?? ""
        let tsRaw = stringField(obj, keys: ["timestamp", "time", "ts", "decision_time"])

        var eventTime = Date()
        if let tsRaw {
            if let d = iso.date(from: tsRaw) ?? isoBasic.date(from: tsRaw) {
                eventTime = d
            }
        }

        var entityRefs: [EntityID] = []
        if !path.isEmpty {
            entityRefs.append(.file(path: path))
            entityRefs.append(.process(pid: 0, path: path))
        } else {
            entityRefs.append(EntityID(kind: .host, value: "santa=decision"))
        }

        var fields: [String: String] = [
            "santa.decision": decision,
            "santa.reason": reason,
            FieldTaxonomy.eventType: "santa.decision",
        ]
        if !path.isEmpty {
            fields[FieldTaxonomy.processPath] = path
            fields[FieldTaxonomy.filePath] = path
            fields["process.path"] = path
        }
        if !sha256.isEmpty {
            fields["santa.sha256"] = sha256
            fields["file.sha256"] = sha256
        }
        if let rule = stringField(obj, keys: ["rule", "rule_name"]) {
            fields["santa.rule"] = rule
        }

        return EventEnvelope(
            identity: .init(kind: "santa.decision", label: "SANTA"),
            capture: .init(source: .santa, eventTime: eventTime),
            payload: .init(entityRefs: entityRefs, properties: fields, provenance: rawRef, confidence: 0.95)
        )
    }

    private static func stringField(_ obj: [String: Any], keys: [String]) -> String? {
        for k in keys {
            if let s = obj[k] as? String, !s.isEmpty { return s }
            if let n = obj[k] as? NSNumber { return n.stringValue }
        }
        return nil
    }
}
