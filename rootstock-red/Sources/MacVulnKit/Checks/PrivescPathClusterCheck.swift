import Foundation
import RootstockCore

/// PEASS-class privilege-escalation **check cluster** (non-vector plane companion).
///
/// Emits ranked misconfiguration findings for:
/// 1. System launchd inventory with user-writable parents
/// 2. Dangerous local sharing combined with weak protections
/// 3. Root assess context with weak host posture
///
/// Research basis: MacPEAS prioritization of privesc / misconfig signals.
/// Safety and behavior: API-first over `CollectedState`, typed Findings, ATT&CK, OPSEC - no shell storms.
public struct PrivescPathClusterCheck: Check {
    public static let id = "rootstock.check.privesc.path_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var findings: [Finding] = []

        if let f = Self.systemLaunchdWritableFinding(state: state) {
            findings.append(f)
        }
        if let f = Self.dangerousSharingFinding(state: state) {
            findings.append(f)
        }
        if let f = Self.rootWeakPostureFinding(state: state) {
            findings.append(f)
        }

        return findings
    }

    // MARK: - Rules

    /// System LaunchAgents/Daemons whose parent directory is user-writable.
    private static func systemLaunchdWritableFinding(state: CollectedState) -> Finding? {
        var hits: [Evidence] = []
        for entry in state.systemLaunchAgents + state.launchDaemons {
            let parent = URL(fileURLWithPath: entry.path).deletingLastPathComponent().path
            let writable =
                FileManager.default.isWritableFile(atPath: entry.path)
                || FileManager.default.isWritableFile(atPath: parent)
            if writable {
                hits.append(
                    Evidence(
                        type: "writable_launchd",
                        path: entry.path,
                        detail: "label=\(entry.label ?? "unknown") parentWritableOrPathWritable=true"
                    )
                )
            }
        }
        // Honor synthetic collector notes used by tests / future collectors.
        if let note = state.collectorNotes["privesc.writable_paths"] {
            for part in note.split(separator: "|") {
                let p = String(part).trimmingCharacters(in: .whitespaces)
                if !p.isEmpty {
                    hits.append(
                        Evidence(
                            type: "writable_launchd",
                            path: p,
                            detail: "source=collectorNotes.privesc.writable_paths"
                        )
                    )
                }
            }
        }
        guard !hits.isEmpty else { return nil }

        return Finding(id: "\(id).system_launchd_writable", title: "Privesc cluster: user-writable system launchd paths (\(hits.count))", severity: .high, category: .misconfig, resolution: .init(evidence: Array(hits.prefix(30)), attackTechniques: ["T1068", "T1543.001", "T1222"], remediation: [
                "Correct ownership to root:wheel and mode 644/755 on system LaunchAgents/Daemons",
                "Investigate how paths became user-writable (installer bug, lab leftover, compromise)",
            ], falsePositiveNotes: "Synthetic lab trees intentionally mark privileged names under temp dirs as writable"), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 26, esfExpected: ["OPEN"]))
    }

    /// File sharing / remote access while protections weak - PEASS “easy win” cluster.
    private static func dangerousSharingFinding(state: CollectedState) -> Finding? {
        guard let net = state.network else { return nil }
        let sharing =
            net.fileSharingSMB == true
            || net.remoteLoginSSH == true
            || net.screenSharingARD == true
        guard sharing else { return nil }

        let weak =
            state.protections?.sipEnabled == false
            || state.protections?.gatekeeperEnabled == false
            || state.protections?.fileVaultOn == false
            || state.host?.isRoot == true
        guard weak else { return nil }

        var evidence: [Evidence] = [
            Evidence(
                type: "sharing",
                detail:
                    "ssh=\(net.remoteLoginSSH.rootstockDescribe) ard=\(net.screenSharingARD.rootstockDescribe) "
                    + "smb=\(net.fileSharingSMB.rootstockDescribe)"
            ),
            Evidence(
                type: "protections",
                detail:
                    "sip=\((state.protections?.sipEnabled).rootstockDescribe) "
                    + "gatekeeper=\((state.protections?.gatekeeperEnabled).rootstockDescribe) "
                    + "filevault=\((state.protections?.fileVaultOn).rootstockDescribe)"
            ),
        ]
        if state.host?.isRoot == true {
            evidence.append(Evidence(type: "context", detail: "assess process isRoot=true"))
        }

        return Finding(id: "\(id).dangerous_sharing", title: "Privesc cluster: remote sharing enabled with weak protections/context", severity: .medium, category: .network, resolution: .init(evidence: evidence, attackTechniques: ["T1021", "T1021.002", "T1021.004", "T1562.001"], remediation: [
                "Disable unused sharing services; require VPN + strong auth if remote admin is needed",
                "Re-enable SIP/Gatekeeper/FileVault per baseline",
            ], falsePositiveNotes: "Admin jump boxes may intentionally combine SSH with hardened controls"), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 18, esfExpected: ["OPEN"]))
    }

    /// Running as root with additional weak signals - prioritize operator awareness.
    private static func rootWeakPostureFinding(state: CollectedState) -> Finding? {
        guard state.host?.isRoot == true else { return nil }
        let weakInject = state.injectabilityHits.contains {
            $0.getTaskAllow == true || $0.hardenedRuntime == false || !$0.riskFlags.isEmpty
        }
        let weakProt = state.protections?.sipEnabled == false
        guard weakInject || weakProt || state.network?.remoteLoginSSH == true else { return nil }

        return Finding(id: "\(id).root_weak_posture", title: "Privesc cluster: root assess context with weak host posture signals", severity: .medium, category: .misconfig, resolution: .init(evidence: [
                Evidence(type: "host", detail: "isRoot=true username=\(state.host?.username ?? "?")"),
                Evidence(
                    type: "signals",
                    detail:
                        "weakInject=\(weakInject) sipDisabled=\(weakProt) "
                        + "ssh=\((state.network?.remoteLoginSSH).rootstockDescribe)"
                ),
            ], attackTechniques: ["T1068", "T1548", "T1078"], remediation: [
                "Prefer least-privilege assess where possible; document root runs in ROE",
                "Harden inject surfaces and re-enable SIP on lab/prod baselines",
            ], falsePositiveNotes: "Authorized root lab runs are valid; finding is posture ranking, not malware"), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 15, esfExpected: ["OPEN"]))
    }

}
