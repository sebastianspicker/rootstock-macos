import Foundation
import RootstockCore

/// Path-to-impact: launchd disabled/override depth (security-product disable class).
///
/// Research basis: disabled.plist defense-evasion (Santa/Falcon/osquery unload class).
/// Safety and behavior: security-hint depth + SIP/remote amplifiers; never disables jobs.
public struct LaunchdOverrideDepthVector: Check {
    public static let id = "rootstock.vector.defense.launchd_override_depth"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard hasSurface(state), hasInventory(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func hasSurface(_ state: CollectedState) -> Bool {
        let lo = state.launchdOverrideDepth
        let overrides = lo?.overridePlistPaths.count ?? 0
        let surface = lo?.overrideSurfacePresent == true || overrides >= 1
        let note = state.collectorNotes["collect.launchd_override_depth"] != nil
        return surface || note
    }

    private func hasInventory(_ state: CollectedState) -> Bool {
        let lo = state.launchdOverrideDepth
        let overrides = lo?.overridePlistPaths.count ?? 0
        let security = lo?.securityDisabledHints.count ?? 0
        return overrides >= 1 || security >= 1
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let lo = state.launchdOverrideDepth
        let overrides = lo?.overridePlistPaths.count ?? 0
        let security = lo?.securityDisabledHints.count ?? 0
        let keepalive = lo?.keepaliveAdjacentPaths.count ?? 0
        let sipOff = state.protections?.sipEnabled == false
        let sensorThin =
            state.esf?.clientPaths.isEmpty == true
            || state.securityProducts.filter(\.present).isEmpty
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true

        var evidence: [Evidence] = [
            Evidence(
                type: "launchd_override_summary",
                detail:
                    "overrides=\(overrides) securityHints=\(security) keepalive=\(keepalive) "
                    + "sipOff=\(sipOff) sensorThin=\(sensorThin) remote=\(remote)"
            ),
        ]
        if let lo {
            for path in lo.overridePlistPaths.prefix(8) {
                evidence.append(Evidence(type: "override_path", path: path, detail: "launchd override/disabled path"))
            }
            for h in lo.securityDisabledHints.prefix(6) {
                evidence.append(Evidence(type: "security_disable_hint", detail: h))
            }
            for n in lo.notes.prefix(6) {
                evidence.append(Evidence(type: "override_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never writes disabled.plist/overrides.plist and never unloads security products."
            )
        )

        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let overrides = state.launchdOverrideDepth?.overridePlistPaths.count ?? 0
        let security = state.launchdOverrideDepth?.securityDisabledHints.count ?? 0
        let sipOff = state.protections?.sipEnabled == false
        let sensorThin = state.esf?.clientPaths.isEmpty == true
            || state.securityProducts.filter(\.present).isEmpty
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let severity: Severity
        if security >= 1 && (sipOff || remote) {
            severity = .high
        } else if security >= 1 || (overrides >= 2 && sensorThin) {
            severity = .medium
        } else {
            severity = .low
        }

        return Finding(id: Self.id, title: security >= 1
                    ? "Launchd override depth with security-product disable hints"
                    : "Launchd disabled / override depth surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1562.001", "T1489", "T1543.004"], remediation: [
                    "Audit /var/db/com.apple.xpc.launchd/disabled*.plist for unexpected security labels",
                    "Alert on launchctl disable of EDR/Santa/osquery labels via MDM/ESF",
                    "Treat SIP-off + security-disable co-presence as high-priority IR",
                    "OPSEC: Rootstock Red does not disable launchd jobs",
                ], falsePositiveNotes: "disabled.plist exists on managed Macs. Elevate when security-product labels appear disabled with remote/SIP amplifiers."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN", "WRITE", "EXEC"]))
    }
}
