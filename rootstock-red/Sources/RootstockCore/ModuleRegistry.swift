import Foundation

/// Compile-time style registry of collectors and checks for a run.
public struct ModuleRegistry: Sendable {
    public var collectors: [any Collector]
    public var checks: [any Check]

    public init(collectors: [any Collector] = [], checks: [any Check] = []) {
        self.collectors = collectors
        self.checks = checks
    }

    public var collectorIds: [String] {
        collectors.map { type(of: $0).id }
    }

    public var checkIds: [String] {
        checks.map { type(of: $0).id }
    }

    /// Filter collectors by scan profile cost.
    public func collectors(for profile: ScanProfile) -> [any Collector] {
        collectors.filter { type(of: $0).cost <= profile.maxCost }
    }

    public func checks(for profile: ScanProfile) -> [any Check] {
        checks.filter { type(of: $0).cost <= profile.maxCost }
    }

    public func collector(id: String) -> (any Collector)? {
        collectors.first { type(of: $0).id == id }
    }
}

/// Run all collectors and merge into one CollectedState.
public enum CollectionRunner {
    public static func run(
        registry: ModuleRegistry,
        context: EvaluationContext,
        onlyIds: Set<String>? = nil
    ) async -> CollectedState {
        var state = CollectedState()
        let selected = registry.collectors(for: context.profile).filter { collector in
            guard let onlyIds else { return true }
            return onlyIds.contains(type(of: collector).id)
        }

        for collector in selected {
            let id = type(of: collector).id
            do {
                let partial = try await collector.collect(context: context)
                state.merge(partial)
            } catch let error as RootstockError {
                if case .tccDenied = error {
                    state.deniedCollectors.append(id)
                    state.collectorNotes[id] = error.localizedDescription
                } else {
                    state.collectorNotes[id] = error.localizedDescription
                }
            } catch {
                state.collectorNotes[id] = error.localizedDescription
            }
        }
        return state
    }
}

/// Run all checks against collected state.
public enum CheckRunner {
    public static func run(
        registry: ModuleRegistry,
        state: CollectedState,
        context: EvaluationContext
    ) async -> [Finding] {
        var findings: [Finding] = []
        for check in registry.checks(for: context.profile) {
            do {
                let result = try await check.evaluate(state: state, context: context)
                findings.append(contentsOf: result)
            } catch {
                findings.append(
                    Finding(id: "rootstock.check.error.\(type(of: check).id)", title: "Check failed: \(type(of: check).id)", severity: .info, category: .other, resolution: .init(evidence: [Evidence(type: "error", detail: error.localizedDescription)]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 0))
                )
            }
        }
        return findings
    }
}
