import Foundation
import RootstockCore

/// Wave-11 compound: launchd override × security-product disable depth.
public struct LaunchdSecurityDisableCompoundVector: Check {
    public static let id = "rootstock.vector.defense.launchd_security_disable_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let lo = state.launchdOverrideDepth
        let overrides = lo?.overridePlistPaths.count ?? 0
        let security = lo?.securityDisabledHints.count ?? 0
        guard overrides >= 1 else { return [] }
        // Compound: override surface + (security hints OR thin sensor OR products absent)
        let productsAbsent = state.securityProducts.filter(\.present).isEmpty
        let sensorThin = state.esf?.clientPaths.isEmpty == true
        guard security >= 1 || productsAbsent || sensorThin else { return [] }

        let sipOff = state.protections?.sipEnabled == false
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let amplified = sipOff || remote || security >= 1

        var evidence: [Evidence] = [
            Evidence(
                type: "launchd_security_disable_compound",
                detail:
                    "overrides=\(overrides) securityHints=\(security) productsAbsent=\(productsAbsent) "
                    + "sensorThin=\(sensorThin) sipOff=\(sipOff) remote=\(remote)"
            ),
        ]
        if let lo {
            for h in lo.securityDisabledHints.prefix(6) {
                evidence.append(Evidence(type: "security_hint", detail: h))
            }
            for path in lo.overridePlistPaths.prefix(6) {
                evidence.append(Evidence(type: "override_path", path: path, detail: "override depth"))
            }
        }
        evidence.append(
            Evidence(type: "honesty", detail: "Never disables launchd jobs or unloads EDR agents.")
        )

        let severity: Severity
        if security >= 1 && (sipOff || remote) {
            severity = .high
        } else if amplified {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(id: Self.id, title: security >= 1
                    ? "Launchd override × security-product disable compound"
                    : "Launchd override × sensor-gap compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1562.001", "T1489"], remediation: [
                    "IR: verify EDR/Santa/osquery labels not present in disabled.plist",
                    "Correlate launchctl disable events with attacker timeline",
                    "OPSEC: assessment narrative only - not a disable toolkit",
                ], falsePositiveNotes: "Managed Macs may legitimately disable lab agents; verify change control."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 30, esfExpected: ["OPEN", "WRITE"])),
        ]
    }
}
