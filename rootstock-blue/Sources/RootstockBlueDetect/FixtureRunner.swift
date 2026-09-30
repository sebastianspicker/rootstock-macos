/// FixtureRunner - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public enum FixtureRunner {
    public static func loadEvents(from url: URL) throws -> [EventEnvelope] {
        try EventJSONL.decode(contentsOf: url)
    }

    public static func evaluate(rule: DetectionRule, events: [EventEnvelope]) -> [Finding] {
        var findings: [Finding] = []
        for event in events where matches(rule: rule, event: event) {
                findings.append(
                    Finding(
                        ruleID: rule.id,
                        title: rule.title,
                        severity: rule.severity,
                        eventIDs: [event.id],
                        attackTechniques: rule.attackTechniques,
                        evidenceSummary: "Matched \(event.eventType) via \(rule.id)"
                    )
                )
        }
        return findings
    }

    public static func matches(rule: DetectionRule, event: EventEnvelope) -> Bool {
        matchesEventType(rule.match.eventType, event: event)
            && matchesFields(rule.match.fieldEquals, against: event.fields, using: ==)
            && matchesFields(rule.match.fieldContains, against: event.fields, using: { $0.contains($1) })
            && hasMatchCriteria(rule)
    }


    private static func matchesEventType(_ expected: String?, event: EventEnvelope) -> Bool {
        expected == nil || expected == event.eventType
    }

    private static func matchesFields(
        _ expected: [String: String]?,
        against fields: [String: String],
        using predicate: (String, String) -> Bool
    ) -> Bool {
        expected?.allSatisfy { key, value in
            guard let actual = fields[key] else { return false }
            return predicate(actual, value)
        } ?? true
    }

    private static func hasMatchCriteria(_ rule: DetectionRule) -> Bool {
        rule.match.eventType != nil
            || rule.match.fieldEquals != nil
            || rule.match.fieldContains != nil
    }
}
