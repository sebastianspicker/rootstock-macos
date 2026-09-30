/// RuleLoader - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public struct DetectionRule: Codable, Sendable {
    public var id: String
    public var title: String
    public var severity: String
    public var description: String
    public var attackTechniques: [String]
    public var match: Match
    public var fixture: String
    public var atomicMapping: String?

    public struct Match: Codable, Sendable {
        public var eventType: String?
        public var fieldEquals: [String: String]?
        public var fieldContains: [String: String]?

        public init(
            eventType: String? = nil,
            fieldEquals: [String: String]? = nil,
            fieldContains: [String: String]? = nil
        ) {
            self.eventType = eventType
            self.fieldEquals = fieldEquals
            self.fieldContains = fieldContains
        }
    }
}

private enum RuleSection {
    case root
    case attack
    case match
    case fieldEquals
    case fieldContains

    var acceptsMatchContent: Bool {
        self == .match || self == .fieldEquals || self == .fieldContains
    }
}

public enum RuleLoader {
    public static func load(from url: URL) throws -> DetectionRule {
        let text = try String(contentsOf: url, encoding: .utf8)
        return try parseSimpleYAML(text, fileName: url.lastPathComponent)
    }

    public static func loadDirectory(_ dir: URL) throws -> [DetectionRule] {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else {
            return []
        }
        return try items
            .filter { $0.pathExtension == "yaml" || $0.pathExtension == "yml" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .map { try load(from: $0) }
    }

    private static func parseSimpleYAML(_ text: String, fileName: String) throws -> DetectionRule {
        var parser = SimpleRuleParser()
        for line in text.components(separatedBy: .newlines) {
            parser.consume(line)
        }
        return try parser.rule(fileName: fileName)
    }

    private struct SimpleRuleParser {
        private var id: String?
        private var title: String?
        private var severity = "medium"
        private var description = ""
        private var fixture: String?
        private var atomicMapping: String?
        private var techniques: [String] = []
        private var eventType: String?
        private var fieldEquals: [String: String] = [:]
        private var fieldContains: [String: String] = [:]
        private var section: RuleSection = .root

        mutating func consume(_ rawLine: String) {
            let source = rawLine.split(separator: "#", maxSplits: 1).first.map(String.init) ?? rawLine
            guard !source.trimmingCharacters(in: .whitespaces).isEmpty else { return }
            let indent = source.prefix(while: { $0 == " " }).count
            let trimmed = source.trimmingCharacters(in: .whitespaces)
            if consumeListItem(trimmed) { return }
            guard let colon = trimmed.firstIndex(of: ":") else { return }
            let key = String(trimmed[..<colon]).trimmingCharacters(in: .whitespaces)
            let value = RuleLoader.unquote(String(trimmed[trimmed.index(after: colon)...]).trimmingCharacters(in: .whitespaces))
            if indent == 0 {
                consumeRoot(key: key, value: value)
            } else {
                consumeNested(key: key, value: value, indent: indent)
            }
        }

        mutating func rule(fileName: String) throws -> DetectionRule {
            guard let id, let title, let fixture else { throw RootstockBlueError.detectionRuleInvalid("missing id/title/fixture in \(fileName)") }
            return DetectionRule(id: id, title: title, severity: severity, description: description, attackTechniques: techniques, match: DetectionRule.Match(eventType: eventType, fieldEquals: fieldEquals.isEmpty ? nil : fieldEquals, fieldContains: fieldContains.isEmpty ? nil : fieldContains), fixture: fixture, atomicMapping: atomicMapping)
        }

        private mutating func consumeListItem(_ line: String) -> Bool {
            guard line.hasPrefix("- ") else { return false }
            if section == .attack { techniques.append(RuleLoader.unquote(String(line.dropFirst(2)))) }
            return true
        }

        private mutating func consumeRoot(key: String, value: String) {
            if setRootScalar(key: key, value: value) {
                section = .root
            } else if key == "attack_techniques" {
                section = .attack
                if !value.isEmpty { techniques.append(value) }
            } else {
                section = key == "match" ? .match : .root
            }
        }

        private mutating func consumeNested(key: String, value: String, indent: Int) {
            guard section.acceptsMatchContent else { return }
            if indent == 2 {
                setMatchSection(key: key, value: value)
            } else if indent >= 4 {
                setMatchField(key: key, value: value)
            }
        }

        private mutating func setRootScalar(key: String, value: String) -> Bool {
            switch key {
            case "id": id = value
            case "title": title = value
            case "severity": severity = value.isEmpty ? severity : value
            case "description": description = value
            case "fixture": fixture = value
            case "atomic_mapping": atomicMapping = value
            default: return false
            }
            return true
        }

        private mutating func setMatchSection(key: String, value: String) {
            switch key {
            case "event_type": eventType = value; section = .match
            case "field_equals": section = .fieldEquals
            case "field_contains": section = .fieldContains
            default: break
            }
        }

        private mutating func setMatchField(key: String, value: String) {
            if section == .fieldEquals { fieldEquals[key] = value }
            if section == .fieldContains { fieldContains[key] = value }
        }
    }

    fileprivate static func unquote(_ s: String) -> String {
        var t = s.trimmingCharacters(in: .whitespaces)
        if t.count >= 2 {
            if (t.hasPrefix("\"") && t.hasSuffix("\"")) || (t.hasPrefix("'") && t.hasSuffix("'")) {
                t.removeFirst()
                t.removeLast()
            }
        }
        return t
    }
}
