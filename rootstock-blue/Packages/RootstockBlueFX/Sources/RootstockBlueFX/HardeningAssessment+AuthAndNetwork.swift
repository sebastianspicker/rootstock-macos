import Foundation
import RootstockBlueCore
import RootstockBlueCase
extension HardeningAssessment {
    static func assessAuthPlugins(_ events: [EventEnvelope]) -> [Finding] {
        let plugins = events.filter {
            $0.sourcePlugin == "AUTHPLUGINS"
                || $0.fields["persistence.kind"] == "authorization_plugin"
                || $0.fields["persistence.kind"] == "auth_plugin"
        }
        guard !plugins.isEmpty else { return [] }
        let risky = plugins.filter(isRiskyAuthorizationPlugin)
        if !risky.isEmpty {
            let names = risky.prefix(5).compactMap {
                $0.fields["auth.plugin_name"] ?? $0.fields["persistence.label"]
            }.joined(separator: ", ")
            return [
                Finding(
                    control: "auth_plugin_unknown",
                    status: "fail",
                    severity: "high",
                    title: "Unknown or risky authorization plugin",
                    detail: "\(risky.count) SecurityAgent/authorization plugin(s) with unknown_vendor/unsigned/tmp risk or non-default names (of \(plugins.count) total).",
                    remediation: "Inventory Library/Security/SecurityAgentPlugins and authorizationdb rights. Remove unauthorized plugins; prefer Apple/MDM-approved auth stacks only. Preserve plugin path and hash before removal (T1556.001-class).",
                    evidence: names
                ),
            ]
        }
        return [
            Finding(
                control: "auth_plugin_unknown",
                status: "warn",
                severity: "low",
                title: "Authorization plugins present",
                detail: "\(plugins.count) authorization plugin(s) inventoried - review for legitimacy.",
                remediation: "Baseline known SecurityAgent plugins; alert on new bundle IDs or paths outside Apple defaults.",
                evidence: plugins.prefix(3).compactMap { $0.fields["auth.plugin_name"] }.joined(separator: ", ")
            ),
        ]
    }

    static func assessNetUsage(_ events: [EventEnvelope]) -> [Finding] {
        let usage = events.filter {
            $0.sourcePlugin == "NETUSAGE"
                || $0.eventType == "network.usage"
                || $0.fields["net.usage.process"] != nil
        }
        guard !usage.isEmpty else { return [] }
        let anomalous = usage.filter(isAnomalousNetworkUsage)
        guard !anomalous.isEmpty else { return [] }
        let sample = anomalous.prefix(3).compactMap {
            let p = $0.fields["net.usage.process"] ?? "?"
            let d = $0.fields["net.usage.domain"] ?? ""
            let b = $0.fields["net.usage.bytes_out"] ?? ""
            return "\(p)→\(d) bytes_out=\(b)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "netusage_anomalous_egress",
                status: "fail",
                severity: "high",
                title: "Anomalous process network usage / egress",
                detail: "\(anomalous.count) process network-usage row(s) with anomalous_egress, high_volume, or suspicious destination signals.",
                remediation: "Correlate net.usage.process with persistence inventory and codesign. Block unexpected egress via ALF/NE/EDR; capture flow metadata (not full PCAP by default). Investigate C2-like domains and unsigned binaries.",
                evidence: sample
            ),
        ]
    }

    static func assessCodesign(_ events: [EventEnvelope]) -> [Finding] {
        let assessments = events.filter {
            $0.sourcePlugin == "CODESIGN"
                || $0.eventType == "codesign.assessment"
                || $0.fields["codesign.path"] != nil
        }
        guard !assessments.isEmpty else { return [] }
        let unsigned = assessments.filter(isUnsignedAssessment)
        guard !unsigned.isEmpty else { return [] }
        let paths = unsigned.prefix(5).compactMap { $0.fields["codesign.path"] }.joined(separator: ", ")
        return [
            Finding(
                control: "unsigned_persistence_binary",
                status: "fail",
                severity: "high",
                title: "Unsigned or non-notarized persistence binary",
                detail: "\(unsigned.count) codesign assessment(s) on persistence-linked paths report unsigned/ad-hoc/not-notarized.",
                remediation: "Quarantine or remove unauthorized unsigned persistence binaries. Prefer notarized, TeamID-allowlisted software. Re-run CODESIGN inventory after remediation; enforce Gatekeeper and MDM software restrictions.",
                evidence: paths
            ),
        ]
    }

    static func assessKeychainMeta(_ events: [EventEnvelope]) -> [Finding] {
        let meta = events.filter {
            $0.sourcePlugin == "KEYCHAINMETA"
                || $0.eventType == "keychain.metadata"
                || $0.fields["keychain.label"] != nil
        }
        guard !meta.isEmpty else { return [] }
        let risky = meta.filter(isRiskyKeychainMetadata)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let label = $0.fields["keychain.label"] ?? "?"
            let group = $0.fields["keychain.access_group"] ?? ""
            return "\(label) group=\(group)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "keychain_metadata_anomaly",
                status: "fail",
                severity: "medium",
                title: "Keychain metadata anomaly (no secrets exported)",
                detail: "\(risky.count) keychain metadata row(s) with suspicious labels/access groups or risk tags. Metadata-only - passwords and private keys are never exported.",
                remediation: "Review keychain item class/label/access_group/mtime against app inventory. Delete unexpected items via Keychain Access or security CLI under change control. Do not dump keychain secrets or private keys into SIEM/JSONL (product non-goal).",
                evidence: sample
            ),
        ]
    }

    static func assessARDAllLocalUsers(_ events: [EventEnvelope]) -> [Finding] {
        let ard = events.filter(isARDPostureEvent)
        let allUsers = ard.contains(where: hasARDAllLocalUsers)
        // Also fail when RemoteManagement plist path implies ARD_AllLocalUsers via IR posture note
        let postureAll = events.contains(where: hasARDPostureMarker)
        guard allUsers || postureAll else { return [] }
        let evidence = ard.prefix(3).compactMap {
            $0.rawRef ?? $0.fields["protection.marker_path"] ?? $0.fields["remote.service"]
        }.joined(separator: " | ")
        return [
            Finding(
                control: "ard_all_local_users",
                status: "fail",
                severity: "high",
                title: "ARD allows all local users",
                detail: "Apple Remote Desktop / Remote Management is configured with ARD_AllLocalUsers (or equivalent all-local-users access policy).",
                remediation: "Disable ARD_AllLocalUsers in com.apple.RemoteManagement.plist; restrict Remote Management to named admin groups via MDM. Prefer VPN-backed ARD with MFA. Audit who has remote-control rights.",
                evidence: evidence.isEmpty ? "ard.all_local_users=true" : evidence
            ),
        ]
    }

    // MARK: - Wave-6 assessments
    private static func isRiskyAuthorizationPlugin(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        let tags = (fields["persistence.risk_tags"] ?? "").lowercased()
        return !tags.isEmpty || containsAny(tags, terms: ["unknown_vendor", "unsigned", "tmp_path"])
            || containsAny((fields["auth.plugin_name"] ?? fields["persistence.label"] ?? "").lowercased(), terms: ["evil", "unknown"])
    }

    private static func isAnomalousNetworkUsage(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return containsAny((fields["net.risk_tags"] ?? "").lowercased(), terms: ["anomalous_egress", "high_volume", "suspicious_process"])
            || containsAny((fields["net.usage.domain"] ?? "").lowercased(), terms: ["evil"])
            || containsAny((fields["net.usage.process"] ?? "").lowercased(), terms: ["evil"])
    }

    private static func isUnsignedAssessment(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        let tags = (fields["codesign.risk_tags"] ?? "").lowercased()
        return containsAny(tags, terms: ["unsigned", "not_notarized", "adhoc"])
            || (fields["codesign.signed"] ?? "").lowercased() == "false"
            || ((fields["codesign.notarized"] ?? "").lowercased() == "false" && tags.contains("unsigned"))
    }

    private static func isRiskyKeychainMetadata(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        let tags = (fields["keychain.risk_tags"] ?? "").lowercased()
        return !tags.isEmpty || containsAny(tags, terms: ["suspicious", "unexpected", "evil"])
            || containsAny((fields["keychain.label"] ?? "").lowercased(), terms: ["evil"])
            || containsAny((fields["keychain.access_group"] ?? "").lowercased(), terms: ["evil"])
    }

    private static func isARDPostureEvent(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        let name = (fields["protection.name"] ?? "").lowercased()
        return [event.sourcePlugin == "ARD", event.eventType == "remote.management", event.eventType == "ir.posture.remote_access" && (containsAny((fields["remote.service"] ?? "").lowercased(), terms: ["ard"]) || containsAny(name, terms: ["remotemanagement", "remote management"])), fields["ard.all_local_users"] != nil, fields["ard.enabled"] != nil].contains(true)
    }

    private static func hasARDAllLocalUsers(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return [fields["ard.all_local_users"] == "true", containsAny((fields["ard.users"] ?? "").lowercased(), terms: ["all"]), fields["ard.allow_all_local_users"] == "true"].contains(true)
    }

    private static func hasARDPostureMarker(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return fields["ard.all_local_users"] == "true" || ((fields["protection.note"] ?? "").contains("ARD_AllLocalUsers") && [fields["protection.enabled"] == "true", fields["remote.enabled"] == "true"].contains(true))
    }
}
