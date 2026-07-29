import Foundation
import RootstockCore

/// Path-to-impact: developer toolchain as dual-use compile / sign / debug surface.
///
/// Research basis: PEASS/LOOBins "dev tools" themes; clang/swift/codesign dual-use catalogs.
/// Safety and behavior: typed DeveloperToolchainState × inject compound; never runs compilers or signs payloads.
public struct DeveloperToolchainDualUseVector: Check {
    public static let id = "rootstock.vector.dev.toolchain_dual_use"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard shouldReport(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func shouldReport(_ state: CollectedState) -> Bool {
        let dev = state.developerToolchain
        let xcode = dev?.xcodePresent == true
        let clt = dev?.commandLineToolsPresent == true
        let dualUse = dev?.dualUseBinaries ?? []
        let toolchainPaths = dev?.toolchainPaths ?? []
        return xcode || clt || dualUse.count >= 2 || collectorNotePresent(state) || !toolchainPaths.isEmpty
    }

    private func collectorNotePresent(_ state: CollectedState) -> Bool {
        let note = state.collectorNotes["collect.developer_toolchain"]
        return note?.contains("xcode=true") == true || note?.contains("clt=true") == true
            || state.collectorNotes["dev.toolchain_present"] != nil
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let dev = state.developerToolchain
        let dualUse = dev?.dualUseBinaries ?? []
        let toolchainPaths = dev?.toolchainPaths ?? []
        let injectRisk = Self.hasInjectRisk(state)
        let highValue = Self.hasHighValueIdentity(state)

        var evidence: [Evidence] = [
            Evidence(
                type: "toolchain_summary",
                detail:
                    "xcode=\((dev?.xcodePresent).rootstockDescribe) "
                    + "clt=\((dev?.commandLineToolsPresent).rootstockDescribe) "
                    + "dualUseBins=\(dualUse.count) toolchainPaths=\(toolchainPaths.count)"
            ),
        ]
        Self.appendPathsAndNotes(to: &evidence, paths: toolchainPaths + dualUse, notes: dev?.notes)
        Self.appendCompounds(to: &evidence, state: state, injectRisk: injectRisk, highValue: highValue)
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Toolchain presence is legitimate on developer workstations. "
                    + "Finding is path-to-impact for dual-use abuse potential - not malware detection."
            )
        )

        return evidence
    }

    private static func hasInjectRisk(_ state: CollectedState) -> Bool {
        state.injectabilityHits.contains { hit in hit.getTaskAllow == true || hit.hardenedRuntime == false || hit.disableLibraryValidation == true || !hit.riskFlags.isEmpty }
    }

    private static func hasHighValueIdentity(_ state: CollectedState) -> Bool {
        state.identity?.adBound == true || state.identity?.platformSSO == true || state.credPaths.contains(where: \.exists)
    }

    private static func appendPathsAndNotes(to evidence: inout [Evidence], paths: [String], notes: [String]?) {
        evidence += paths.prefix(12).map { Evidence(type: "toolchain_path", path: $0, detail: "dual-use toolchain path") }
        evidence += (notes ?? []).prefix(8).map { Evidence(type: "dev_note", detail: $0) }
    }

    private static func appendCompounds(to evidence: inout [Evidence], state: CollectedState, injectRisk: Bool, highValue: Bool) {
        if injectRisk { evidence.append(Evidence(type: "compound_inject", detail: "injectabilityHits=\(state.injectabilityHits.count) " + "(get-task-allow / HR-off / LV-off compound)")) }
        if highValue { evidence.append(Evidence(type: "compound_high_value", detail: "adBound=\((state.identity?.adBound).rootstockDescribe) " + "platformSSO=\((state.identity?.platformSSO).rootstockDescribe) " + "credPaths=\(state.credPaths.filter(\.exists).count)")) }
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let dev = state.developerToolchain
        let xcode = dev?.xcodePresent == true
        let clt = dev?.commandLineToolsPresent == true
        let dualUse = dev?.dualUseBinaries ?? []
        let injectRisk = hasInjectRisk(state)
        let severity: Severity = (injectRisk && (xcode || clt || dualUse.count >= 3)) ? .medium : .low
        return Finding(id: Self.id, title: injectRisk
                    ? "Developer toolchain dual-use surface compounds with injectability signals"
                    : "Developer toolchain dual-use surface (Xcode/CLT/compile-sign bins)", severity: severity, category: .codesign, resolution: .init(evidence: evidence, attackTechniques: ["T1059", "T1127", "T1553.002", "T1588.002"], remediation: [
                    "Limit Xcode/CLT install on non-developer high-value hosts via MDM",
                    "Monitor codesign / clang / lldb execution on production endpoints",
                    "Prefer signed CI builders over interactive toolchain on identity-joined laptops when possible",
                    "OPSEC: Rootstock Red never invokes compilers or signs payloads",
                ], falsePositiveNotes: "Developer Macs legitimately host full toolchains; prioritize compounds with inject/identity."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 22, esfExpected: ["EXEC", "OPEN"]))
    }

}
