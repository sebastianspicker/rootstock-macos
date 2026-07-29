import Foundation
import RootstockCore

/// Injectability / codesign surface: HR off or dangerous entitlements → medium/high.
public struct CodesignInjectSurfaceCheck: Check {
    public static let id = "rootstock.check.codesign.inject_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let hits = state.injectabilityHits
        let samples = state.codesignSamples
        guard !hits.isEmpty || !samples.isEmpty else { return [] }
        let risky = hits.filter { !$0.riskFlags.isEmpty }
        return [Self.finding(hits: hits, samples: samples, risky: risky, state: state)]
    }

    private static func finding(hits: [InjectabilityHit], samples: [CodesignSample], risky: [InjectabilityHit], state: CollectedState) -> Finding {
        let highRisk = risky.filter { $0.riskFlags.contains("get-task-allow") || $0.riskFlags.contains("allow-unsigned-executable-memory") || $0.riskFlags.contains("disable-library-validation") }
        let title = !highRisk.isEmpty ? "Dangerous inject surface entitlements (\(highRisk.count) samples)" : !risky.isEmpty ? "Inject surface risks (\(risky.count) samples)" : "Codesign / inject surface samples (\(max(hits.count, samples.count)))"
        let severity: Severity = !highRisk.isEmpty ? .high : !risky.isEmpty ? .medium : .info
        return Finding(id: Self.id, title: title, severity: severity, category: .codesign, resolution: .init(evidence: evidence(hits: hits, samples: samples, risky: risky, state: state), attackTechniques: ["T1055", "T1574.006"], remediation: ["Prefer Hardened Runtime without get-task-allow on production builds", "Avoid disable-library-validation and allow-dyld-environment-variables unless required", "Developer builds with get-task-allow are expected on engineering workstations"], falsePositiveNotes: "Debug-signed local builds commonly include get-task-allow"), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 15, esfExpected: ["OPEN"]))
    }

    private static func evidence(hits: [InjectabilityHit], samples: [CodesignSample], risky: [InjectabilityHit], state: CollectedState) -> [Evidence] {
        var result = risky.isEmpty ? (samples.isEmpty ? hits.map(\.path) : samples.map(\.path)).prefix(15).map { Evidence(type: "codesign_sample", path: $0, detail: "no elevated inject flags") } : risky.prefix(25).map { Evidence(type: "inject_risk", path: $0.path, detail: "flags=\($0.riskFlags.joined(separator: ","))") }
        if risky.isEmpty { result += hits.prefix(10).map { Evidence(type: "injectability", path: $0.path, detail: "HR=\($0.hardenedRuntime.map { $0 ? "on" : "off" } ?? "unknown") flags=none") } }
        result += state.dylibRiskHits.prefix(10).map { Evidence(type: "dylib_risk", path: $0.path, detail: $0.weakDylibs.isEmpty ? $0.notes.joined(separator: "; ") : "weak=\($0.weakDylibs.joined(separator: ","))") }
        return result
    }
}
