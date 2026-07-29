import Foundation
import RootstockCore

/// Delivery / trust surface cluster: quarantine xattrs × XProtect inventory × GK+remote compound.
///
/// Research basis: PEASS download-quarantine themes; XProtect inventory; remote-access trust gaps.
/// Safety and behavior: multi-rule API-first Findings over CollectedState + local path probe; no quarantine strip,
/// no XProtect bypass, no Gatekeeper disable tooling.
public struct DeliveryTrustClusterCheck: Check {
    public static let id = "rootstock.check.vuln.delivery_trust_cluster"
    public static let cost: CollectorCost = .low

    public static let xprotectBundlePath =
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle"

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var findings: [Finding] = []
        if let f = Self.quarantineHits(state: state) { findings.append(f) }
        if let f = Self.xprotectSurface() { findings.append(f) }
        if let f = Self.gatekeeperOffWithRemote(state: state) { findings.append(f) }
        return findings
    }

    // MARK: - Rules

    /// Quarantine delivery signals from collector notes or protections notes.
    private static func quarantineHits(state: CollectedState) -> Finding? {
        var evidence: [Evidence] = []

        if let note = state.collectorNotes["codesign.quarantine_hits"], !note.isEmpty {
            evidence.append(
                Evidence(
                    type: "collector_note",
                    detail: "codesign.quarantine_hits=\(note)"
                )
            )
            for part in note.split(separator: "|") {
                let p = String(part).trimmingCharacters(in: .whitespaces)
                if !p.isEmpty {
                    evidence.append(
                        Evidence(
                            type: "quarantine_hit",
                            path: p,
                            detail: "source=collectorNotes.codesign.quarantine_hits"
                        )
                    )
                }
            }
        }

        let protNotes = state.protections?.notes ?? []
        let quarantineNotes = protNotes.filter {
            $0.localizedCaseInsensitiveContains("quarantine")
        }
        for note in quarantineNotes.prefix(12) {
            evidence.append(Evidence(type: "protection_note", detail: note))
        }

        guard !evidence.isEmpty else { return nil }

        return Finding(id: "\(id).quarantine_hits", title: "Delivery-trust cluster: quarantine / download-delivery signals present", severity: .low, category: .codesign, resolution: .init(evidence: Array(evidence.prefix(30)), attackTechniques: ["T1553.001", "T1204.002", "T1105"], remediation: [
                "Inventory com.apple.quarantine xattrs on managed download paths via MDM",
                "Do not mass-strip quarantine; prefer Gatekeeper + notarization policy",
                "Correlate download provenance with allowlisted installers only",
            ], falsePositiveNotes: "Legitimate user downloads commonly carry quarantine; this is surface inventory, not malware"), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 12, esfExpected: ["OPEN"]))
    }

    /// Built-in XProtect definitions bundle path - inventory only (not a bypass check).
    private static func xprotectSurface() -> Finding? {
        let path = xprotectBundlePath
        let present = FileManager.default.fileExists(atPath: path)
        // Always emit when present (expected on modern macOS) as info/low inventory;
        // when absent, emit low so operators notice a missing Apple malware-defs surface.
        let severity: Severity = present ? .info : .low
        let title = present
            ? "Delivery-trust cluster: XProtect.bundle present (built-in malware defs surface)"
            : "Delivery-trust cluster: XProtect.bundle path missing"

        return Finding(id: "\(id).xprotect_surface", title: title, severity: severity, category: .securityProduct, resolution: .init(evidence: [
                Evidence(
                    type: "xprotect",
                    path: path,
                    detail: "present=\(present) (path probe only - not an XProtect bypass)"
                ),
            ], attackTechniques: ["T1518.001", "T1082"], remediation: [
                "Confirm XProtect / XProtect Remediator updates via softwareupdate / MDM",
                "Do not disable or replace Apple malware definitions on managed fleets",
            ], falsePositiveNotes: "Some recovery / custom OS images may omit the standard XProtect.bundle path"), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 8, esfExpected: ["OPEN"]))
    }

    /// Gatekeeper disabled compounded with remote access (SSH / ARD).
    private static func gatekeeperOffWithRemote(state: CollectedState) -> Finding? {
        guard state.protections?.gatekeeperEnabled == false else { return nil }
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        guard remote else { return nil }

        return Finding(id: "\(id).gatekeeper_off_with_remote", title: "Delivery-trust cluster: Gatekeeper off with remote access enabled", severity: .high, category: .codesign, resolution: .init(evidence: [
                Evidence(type: "gatekeeper", detail: "gatekeeperEnabled=false"),
                Evidence(
                    type: "remote",
                    detail:
                        "ssh=\((state.network?.remoteLoginSSH).rootstockDescribe) "
                        + "ard=\((state.network?.screenSharingARD).rootstockDescribe)"
                ),
            ], attackTechniques: ["T1553.001", "T1021", "T1021.004", "T1204.002"], remediation: [
                "Re-enable Gatekeeper via MDM compliance",
                "Disable unused Remote Login / Screen Sharing; require VPN + MFA for remote admin",
                "Prioritize hosts that combine remote access with weakened trust-chain controls",
            ], falsePositiveNotes: "Isolated lab VMs may intentionally disable GK with remote console"), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 18, esfExpected: ["OPEN"]))
    }

}
