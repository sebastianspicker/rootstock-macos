import Foundation
import RootstockBlueCore

public struct DetectionEngine: Sendable {
    public init() {}

    /// Load rules from a directory; each rule must reference a fixture file.
    public func run(rulesDirectory: URL, fixturesDirectory: URL) throws -> [Finding] {
        let rules = try RuleLoader.loadDirectory(rulesDirectory)
        var all: [Finding] = []
        for rule in rules {
            let fixtureURL = fixturesDirectory.appendingPathComponent(rule.fixture)
            guard FileManager.default.fileExists(atPath: fixtureURL.path) else {
                throw RootstockBlueError.fixtureMissing(fixtureURL.path)
            }
            let events = try FixtureRunner.loadEvents(from: fixtureURL)
            all.append(contentsOf: FixtureRunner.evaluate(rule: rule, events: events))
        }
        return all
    }

    /// Evaluate loaded rules against an in-memory event set (case timeline / parse output).
    /// Does not require per-rule JSONL fixtures - uses the real case-loaded events.
    public func evaluate(rules: [DetectionRule], events: [EventEnvelope]) -> [Finding] {
        var all: [Finding] = []
        for rule in rules {
            all.append(contentsOf: FixtureRunner.evaluate(rule: rule, events: events))
        }
        return all
    }

    /// Load rules from directory and evaluate against case/timeline events.
    public func evaluate(rulesDirectory: URL, events: [EventEnvelope]) throws -> [Finding] {
        let rules = try RuleLoader.loadDirectory(rulesDirectory)
        return evaluate(rules: rules, events: events)
    }

    public func validateRuleHasFixture(rule: DetectionRule, fixturesDirectory: URL) throws {
        let fixtureURL = fixturesDirectory.appendingPathComponent(rule.fixture)
        guard FileManager.default.fileExists(atPath: fixtureURL.path) else {
            throw RootstockBlueError.fixtureMissing(rule.fixture)
        }
    }
}
