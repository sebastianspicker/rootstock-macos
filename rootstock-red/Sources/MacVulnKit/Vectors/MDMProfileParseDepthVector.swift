import Foundation
import RootstockCore

/// Path-to-impact: MDM/mobileconfig shallow parse depth surface.
///
/// Research basis: Configuration Profile PayloadType taxonomy; enterprise sideload research.
/// Safety and behavior: PayloadType inventory compounds with enrollment gap; never dumps secrets.
public struct MDMProfileParseDepthVector: Check {
    public static let id = "rootstock.vector.mdm.profile_parse_depth"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard hasSurface(state), hasInventory(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func hasSurface(_ state: CollectedState) -> Bool {
        let mp = state.mdmProfileParseDepth
        let examined = mp?.examinedProfilePaths.count ?? 0
        let parsed = mp?.parsedProfileCount ?? 0
        let surface = mp?.parseSurfacePresent == true || examined > 0 || parsed > 0
        let note = state.collectorNotes["collect.mdm_profile_parse_depth"] != nil
        return surface || note
    }

    private func hasInventory(_ state: CollectedState) -> Bool {
        let mp = state.mdmProfileParseDepth
        let parsed = mp?.parsedProfileCount ?? 0
        let examined = mp?.examinedProfilePaths.count ?? 0
        let unmanaged = state.mdm?.enrolled != true
        let hasRootNote = mp?.notes.contains(where: { $0.hasPrefix("profile_root:") }) == true
        return parsed >= 1 || examined >= 1 || (unmanaged && hasRootNote)
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let mp = state.mdmProfileParseDepth
        let examined = mp?.examinedProfilePaths.count ?? 0
        let parsed = mp?.parsedProfileCount ?? 0
        let types = mp?.payloadTypes.count ?? 0
        let unmanaged = state.mdm?.enrolled != true
        let sideload = (state.configProfileSideload?.userMobileconfigPaths.count ?? 0) > 0
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true

        var evidence: [Evidence] = [
            Evidence(
                type: "profile_parse_summary",
                detail:
                    "examined=\(examined) parsed=\(parsed) types=\(types) "
                    + "displayName=\(mp?.displayNamePresent.map(String.init(describing:)) ?? "nil") "
                    + "unmanaged=\(unmanaged) sideload=\(sideload) remote=\(remote)"
            ),
        ]
        if let mp {
            for t in mp.payloadTypes.prefix(16) {
                evidence.append(Evidence(type: "payload_type", detail: t))
            }
            for path in mp.examinedProfilePaths.prefix(8) {
                evidence.append(Evidence(type: "profile_path", path: path, detail: "examined mobileconfig"))
            }
            for n in mp.notes.prefix(6) {
                // Filter secret values if any slipped; notes should already be key-names only.
                if n.lowercased().contains("password=") { continue }
                evidence.append(Evidence(type: "profile_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess performs shallow PayloadType / PayloadDisplayName inventory only. "
                    + "Never dumps passwords, certificates, shared secrets, or installs profiles."
            )
        )

        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let parsed = state.mdmProfileParseDepth?.parsedProfileCount ?? 0
        let examined = state.mdmProfileParseDepth?.examinedProfilePaths.count ?? 0
        let unmanaged = state.mdm?.enrolled != true
        let sideload = (state.configProfileSideload?.userMobileconfigPaths.count ?? 0) > 0
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let severity: Severity
        if unmanaged && parsed >= 1 && (sideload || remote) {
            severity = .medium
        } else if parsed >= 1 || (unmanaged && examined >= 1) {
            severity = .low
        } else {
            severity = .info
        }

        return Finding(id: Self.id, title: unmanaged && parsed >= 1
                    ? "Parseable mobileconfig profiles on unmanaged host"
                    : "MDM profile shallow parse depth posture", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1556", "T1484"], remediation: [
                    "Block user-installed configuration profiles via MDM where policy allows",
                    "Educate users against opening unsolicited .mobileconfig from email/web",
                    "Inventory PayloadTypes on engagement hosts; remove unexpected VPN/WiFi/PPPC profiles",
                    "OPSEC: Rootstock Red does not install profiles or dump secret payload values",
                ], falsePositiveNotes: "Managed fleets may legitimately host many profiles. Prioritize unmanaged hosts "
                    + "with user-writable .mobileconfig files."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 16, esfExpected: ["OPEN", "READ"]))
    }
}
