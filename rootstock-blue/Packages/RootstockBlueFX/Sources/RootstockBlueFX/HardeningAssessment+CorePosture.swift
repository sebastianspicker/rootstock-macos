import Foundation
import RootstockBlueCore
import RootstockBlueCase
extension HardeningAssessment {
    static func assessProtections(_ events: [EventEnvelope]) -> [Finding] {
        let protections = events.filter {
            $0.eventType == "ir.posture.protection" || $0.fields["protection.name"] != nil
        }
        return [
            sipProtectionFinding(protections),
            firewallProtectionFinding(protections),
            gatekeeperProtectionFinding(protections),
            fileVaultProtectionFinding(protections),
        ].compactMap { $0 }
    }

    private static func protectionStatus(_ name: String, in events: [EventEnvelope]) -> (enabled: String, evidence: String)? {
        events.first { event in
            let candidate = (event.fields["protection.name"] ?? "").lowercased()
            return candidate == name.lowercased() || candidate.contains(name.lowercased())
        }.map {
            ($0.fields["protection.enabled"] ?? "unknown", $0.fields["protection.raw"] ?? $0.fields["protection.note"] ?? "")
        }
    }

    private static func sipProtectionFinding(_ events: [EventEnvelope]) -> Finding? {
        guard let status = protectionStatus("SIP", in: events) else { return nil }
        switch status.enabled {
        case "false":
            return Finding(control: "sip", status: "fail", severity: "critical", title: "System Integrity Protection disabled", detail: "SIP is reported disabled. Kernel and critical paths are less protected.", remediation: "Re-enable SIP from Recovery: csrutil enable; reboot. Investigate who disabled it.", evidence: status.evidence)
        case "true":
            return Finding(control: "sip", status: "pass", severity: "info", title: "SIP enabled", detail: "System Integrity Protection appears enabled.", remediation: "No action. Keep SIP enabled except during short, controlled maintenance.", evidence: status.evidence)
        default:
            return Finding(control: "sip", status: "unknown", severity: "low", title: "SIP status unknown", detail: "Could not determine SIP state from available posture signals.", remediation: "Run live: csrutil status. Prefer offline security_posture.json in images.", evidence: status.evidence)
        }
    }

    private static func firewallProtectionFinding(_ events: [EventEnvelope]) -> Finding? {
        guard let status = protectionStatus("Firewall", in: events) else { return nil }
        switch status.enabled {
        case "false":
            return Finding(control: "firewall", status: "fail", severity: "high", title: "Application firewall disabled", detail: "ALF / application firewall is reported off.", remediation: "Enable Application Firewall (Security settings or /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on). Enforce via MDM where possible.", evidence: status.evidence)
        case "true":
            return Finding(control: "firewall", status: "pass", severity: "info", title: "Firewall enabled", detail: "Application firewall appears enabled.", remediation: "Confirm stealth mode and block-all-incoming policy match org baseline.", evidence: status.evidence)
        default:
            return nil
        }
    }

    private static func gatekeeperProtectionFinding(_ events: [EventEnvelope]) -> Finding? {
        guard let status = protectionStatus("Gatekeeper", in: events) else { return nil }
        switch status.enabled {
        case "false":
            return Finding(control: "gatekeeper", status: "fail", severity: "high", title: "Gatekeeper disabled", detail: "Gatekeeper assessments appear disabled - unsigned/unknown code easier to run.", remediation: "Re-enable: spctl --master-enable. Investigate recent Gatekeeper overrides and quarantine events.", evidence: status.evidence)
        case "true":
            return Finding(control: "gatekeeper", status: "pass", severity: "info", title: "Gatekeeper enabled", detail: "Gatekeeper appears enabled.", remediation: "Monitor GATEKEEPER_USER_OVERRIDE and assessment history.", evidence: status.evidence)
        default:
            return nil
        }
    }

    private static func fileVaultProtectionFinding(_ events: [EventEnvelope]) -> Finding? {
        guard let status = protectionStatus("FileVault", in: events) else { return nil }
        switch status.enabled {
        case "false":
            return Finding(control: "filevault", status: "fail", severity: "high", title: "FileVault disk encryption disabled", detail: "Volume encryption is reported off - data-at-rest risk if device is stolen.", remediation: "Enable FileVault via System Settings or MDM escrow. Never attempt offline cryptanalysis (non-goal).", evidence: status.evidence)
        case "true":
            return Finding(control: "filevault", status: "pass", severity: "info", title: "FileVault enabled", detail: "Disk encryption appears enabled.", remediation: "Verify institutional recovery key escrow with MDM.", evidence: status.evidence)
        default:
            return nil
        }
    }

    static func assessRemoteAccess(_ events: [EventEnvelope]) -> [Finding] {
        var seenControls = Set<String>()
        let liveFindings = events.flatMap { remoteServiceFindings(for: $0, seenControls: &seenControls) }
        let postureFindings = events.compactMap { legacyRemoteAccessFinding(for: $0, seenControls: &seenControls) }
        return liveFindings + postureFindings
    }

    private struct RemoteServiceRule: @unchecked Sendable {
        let control: String
        let status: String
        let severity: String
        let title: String
        let detail: String
        let remediation: String
        let matches: (String, String) -> Bool
        let evidence: (EventEnvelope, String, String) -> String
    }

    private static let remoteServiceRules: [RemoteServiceRule] = [
        RemoteServiceRule(control: "screen_sharing", status: "fail", severity: "high", title: "Screen Sharing enabled", detail: "Remote screen sharing appears enabled - increase remote-access attack surface.", remediation: "Disable Screen Sharing unless required. Prefer MDM-managed ARD with MFA/VPN. Review /Library/Preferences/com.apple.RemoteManagement.plist and sharing prefs.", matches: { name, service in containsAny(name, terms: ["screen"]) || containsAny(service, terms: ["screen"]) }, evidence: { event, name, _ in event.rawRef ?? event.fields["remote.name"] ?? name }),
        RemoteServiceRule(control: "remote_management", status: "warn", severity: "medium", title: "Remote Management (ARD) enabled", detail: "Apple Remote Desktop / remote management appears enabled.", remediation: "Restrict to admin group; require VPN; audit who has ARD rights.", matches: { name, service in containsAny(name, terms: ["remote management", "remotemanagement", "ard"]) || containsAny(service, terms: ["ard"]) }, evidence: { event, _, _ in event.rawRef ?? "" }),
        RemoteServiceRule(control: "remote_login", status: "fail", severity: "high", title: "Remote Login (sshd) enabled", detail: "Remote Login / SSH service appears enabled on this host/image.", remediation: "Disable Remote Login in System Settings → General → Sharing unless required. Prefer VPN + key-only SSH; enforce via MDM. Audit authorized_keys (SSH parser).", matches: { name, service in containsAny(name, terms: ["remotelogin", "remote login", "sshd"]) || service == "ssh" || containsAny(service, terms: ["sshd"]) }, evidence: { event, _, service in event.rawRef ?? service }),
        RemoteServiceRule(control: "file_sharing", status: "fail", severity: "medium", title: "File Sharing enabled", detail: "SMB/AFP File Sharing appears enabled - lateral movement surface on laptops.", remediation: "Disable File Sharing unless business-required; restrict users/shares; prefer managed file services over ad-hoc SMB.", matches: { name, service in containsAny(name, terms: ["filesharing", "file sharing"]) || containsAny(service, terms: ["file_sharing", "smb"]) }, evidence: { event, _, service in event.rawRef ?? service }),
    ]

    private static func remoteServiceFindings(for event: EventEnvelope, seenControls: inout Set<String>) -> [Finding] {
        let fields = event.fields
        let name = (fields["remote.name"] ?? fields["protection.name"] ?? "").lowercased()
        let service = (fields["remote.service"] ?? fields[FieldTaxonomy.remoteService] ?? name).lowercased()
        let enabled = fields["remote.enabled"] ?? fields[FieldTaxonomy.remoteEnabled] ?? fields["protection.enabled"] ?? ""
        guard ["true", "present"].contains(enabled) else { return [] }
        return remoteServiceRules.compactMap { rule in
            guard rule.matches(name, service), seenControls.insert(rule.control).inserted else { return nil }
            return Finding(control: rule.control, status: rule.status, severity: rule.severity, title: rule.title, detail: rule.detail, remediation: rule.remediation, evidence: rule.evidence(event, name, service))
        }
    }

    private static func legacyRemoteAccessFinding(for event: EventEnvelope, seenControls: inout Set<String>) -> Finding? {
        let fields = event.fields
        guard event.sourcePlugin == "IRPOSTURE", [fields["remote.enabled"] == "true", fields["screen_sharing_enabled"] == "true"].contains(true), seenControls.insert("screen_sharing").inserted else { return nil }
        let service = fields["remote.name"] ?? fields["remote.service"] ?? fields["protection.name"] ?? "remote"
        guard containsAny(service.lowercased(), terms: ["screen"]) || event.eventType.contains("remote") else { return nil }
        return Finding(control: "screen_sharing", status: "fail", severity: "high", title: "Screen Sharing / remote access enabled", detail: "IR posture reports remote access service enabled (\(service)).", remediation: "Disable unneeded remote services; enforce via configuration profile.", evidence: event.rawRef ?? service)
    }

    static func assessLaunchdOverrides(_ events: [EventEnvelope]) -> [Finding] {
        let disabledSecurity = events.filter {
            $0.eventType == "defense.launchd_override"
                && $0.fields["defense.disabled"] == "true"
                && $0.fields["defense.security_product_hint"] == "true"
        }
        guard !disabledSecurity.isEmpty else { return [] }
        let labels = disabledSecurity.compactMap { $0.fields["defense.label"] }.joined(separator: ", ")
        return [
            Finding(
                control: "launchd_security_disabled",
                status: "fail",
                severity: "critical",
                title: "Security-related launchd jobs disabled",
                detail: "One or more security/IR agents appear in launchd disabled overrides: \(labels)",
                remediation: "Re-enable legitimate agents (launchctl enable). Investigate who wrote disabled.plist. Preserve overrides for forensics before remediation.",
                evidence: labels
            ),
        ]
    }

    static func assessSudoers(_ events: [EventEnvelope]) -> [Finding] {
        let risky = events.filter {
            $0.eventType == "privilege.sudoers"
                && ($0.fields["privilege.risk_tags"]?.contains("nopasswd") == true
                    || $0.fields["sudoers.risk"]?.contains("nopasswd") == true
                    || $0.fields["privilege.risk_tags"]?.contains("broad_grant") == true)
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap { $0.fields["privilege.line"] ?? $0.fields["sudoers.entry"] }.joined(separator: " | ")
        return [
            Finding(
                control: "sudoers_nopasswd",
                status: "fail",
                severity: "high",
                title: "Dangerous sudoers grant (NOPASSWD / broad ALL)",
                detail: "sudoers entries allow passwordless or overly broad privilege elevation (\(risky.count) matching lines).",
                remediation: "Remove NOPASSWD and ALL=(ALL) ALL grants not justified by break-glass policy. Prefer group-scoped, command-limited sudo. Audit /etc/sudoers.d regularly.",
                evidence: sample
            ),
        ]
    }

    static func assessShellProfiles(_ events: [EventEnvelope]) -> [Finding] {
        let risky = events.filter {
            $0.sourcePlugin == "SHELLPROFILES"
                && $0.fields["persistence.risk_tags"] != nil
                && !($0.fields["persistence.risk_tags"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let tags = Set(risky.flatMap { ($0.fields["persistence.risk_tags"] ?? "").split(separator: ",").map(String.init) })
        return [
            Finding(
                control: "shell_profile_risk",
                status: "fail",
                severity: tags.contains("curl_pipe_shell") || tags.contains("dyld_insert") ? "high" : "medium",
                title: "Suspicious shell profile content",
                detail: "Shell init files contain high-risk patterns: \(tags.sorted().joined(separator: ", "))",
                remediation: "Inspect user/system profiles for unauthorized PATH, DYLD_INSERT_LIBRARIES, curl|sh, or /tmp payloads. Diff against golden images / MDM baselines.",
                evidence: risky.prefix(3).compactMap { $0.fields["persistence.command"] }.joined(separator: " | ")
            ),
        ]
    }

    static func assessEmond(_ events: [EventEnvelope]) -> [Finding] {
        let emond = events.filter {
            $0.sourcePlugin == "EMOND" || $0.fields["persistence.kind"] == "emond"
        }
        guard !emond.isEmpty else { return [] }
        // Non-Apple / tmp commands are higher risk
        let suspicious = emond.filter {
            let cmd = ($0.fields["persistence.command"] ?? "").lowercased()
            return cmd.contains("/tmp/") || cmd.contains("curl") || cmd.contains("evil")
                || !cmd.contains("com.apple")
        }
        if !suspicious.isEmpty {
            return [
                Finding(
                    control: "emond_rules",
                    status: "fail",
                    severity: "high",
                    title: "Emond rules present (potential persistence)",
                    detail: "Event Monitor Daemon rules found (\(emond.count)); \(suspicious.count) look non-default/suspicious.",
                    remediation: "Inventory /etc/emond.d/rules. Remove unauthorized rules. Emond is rare on modern fleets - treat unexpected rules as high priority.",
                    evidence: suspicious.prefix(3).compactMap { $0.fields["persistence.command"] ?? $0.fields["emond.rule_name"] }.joined(separator: " | ")
                ),
            ]
        }
        return [
            Finding(
                control: "emond_rules",
                status: "warn",
                severity: "low",
                title: "Emond rules inventory non-empty",
                detail: "\(emond.count) emond rule(s) present - review for legitimacy.",
                remediation: "Confirm rules are organization-approved; otherwise remove.",
                evidence: ""
            ),
        ]
    }

    static func assessSystemExtensions(_ events: [EventEnvelope]) -> [Finding] {
        let sysext = events.filter {
            $0.eventType.contains("sysext")
                || $0.fields["extension.bundle_id"] != nil
                || $0.sourcePlugin == "SYSTEMEXTENSIONS"
        }
        let unknown = sysext.filter {
            let team = ($0.fields["extension.team_id"] ?? $0.fields[FieldTaxonomy.extensionTeamID] ?? "").lowercased()
            let bundle = ($0.fields["extension.bundle_id"] ?? $0.fields[FieldTaxonomy.extensionBundleID] ?? "").lowercased()
            return bundle.contains("evil") || bundle.contains("unknown")
                || team == "unknown" || team.isEmpty && !bundle.hasPrefix("com.apple")
        }
        guard !unknown.isEmpty else { return [] }
        return [
            Finding(
                control: "system_extensions",
                status: "warn",
                severity: "medium",
                title: "Unknown or suspicious system extensions",
                detail: "\(unknown.count) system extension(s) lack trusted team/bundle signals.",
                remediation: "systemextensionsctl list; remove unauthorized sysexts; require notarization + MDM allowlist for ES/NE peers.",
                evidence: unknown.prefix(3).compactMap { $0.fields["extension.bundle_id"] ?? $0.fields[FieldTaxonomy.extensionBundleID] }.joined(separator: ", ")
            ),
        ]
    }

    static func assessSecurityCoverage(_ events: [EventEnvelope]) -> [Finding] {
        let products = events.filter { $0.eventType == "ir.posture.security_product" || $0.fields["security.product"] != nil }
        if products.isEmpty {
            // Only warn if we have some host posture so we know we scanned
            let hasHost = events.contains { $0.eventType == "ir.posture.host" }
            if hasHost {
                return [
                    Finding(
                        control: "edr_coverage",
                        status: "warn",
                        severity: "medium",
                        title: "No known security product detected on host/image",
                        detail: "Catalog paths for Falcon/Santa/MDE/osquery/etc. were not present.",
                        remediation: "Confirm fleet EDR/osquery/Santa deployment. RootstockBlue is Mac depth beside EDR - not a replacement.",
                        evidence: "security product catalog empty"
                    ),
                ]
            }
        }
        return []
    }

    // MARK: - Wave-4 assessments
}
