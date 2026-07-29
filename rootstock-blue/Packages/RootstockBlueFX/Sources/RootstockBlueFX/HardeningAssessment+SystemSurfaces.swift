import Foundation
import RootstockBlueCore
import RootstockBlueCase
extension HardeningAssessment {
    static func assessAutomatorWorkflow(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "AUTOMATORWF" || $0.eventType == "automator.workflow"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["automator.risk_tags"] ?? "").lowercased()
            return tags.contains("workflow_surface") || !($0.fields["automator.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["automator.path"] ?? ""
            let name = $0.fields["automator.name"] ?? ""
            let tags = $0.fields["automator.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "automator_workflow", status: "fail", severity: "medium",
            title: "Automator workflow delivery residual surface present",
            detail: "\(risky.count) Automator workflow delivery marker(s) - IR surface. Path/meta only; never executes Automator workflows or plants malicious .workflow bundles.",
            remediation: "Inventory and baseline Automator workflow delivery artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessIcloudDrivePath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "ICLOUDDRIVEPATH" || $0.eventType == "icloud.drive_path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["icldrv.risk_tags"] ?? "").lowercased()
            return tags.contains("icloud_path_surface") || !($0.fields["icldrv.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["icldrv.path"] ?? ""
            let name = $0.fields["icldrv.name"] ?? ""
            let tags = $0.fields["icldrv.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "icloud_drive_path", status: "fail", severity: "medium",
            title: "iCloud Drive / Mobile Documents path plane surface present",
            detail: "\(risky.count) iCloud Drive path plane marker(s) - IR surface. Path/meta only; never enumerates iCloud file contents or exfiltrates Mobile Documents.",
            remediation: "Inventory and baseline iCloud Drive path plane artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessBluetoothContinuityDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "BTCONTINUITY" || $0.eventType == "bluetooth.continuity"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["btcont.risk_tags"] ?? "").lowercased()
            return tags.contains("bt_continuity_surface") || !($0.fields["btcont.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["btcont.path"] ?? ""
            let name = $0.fields["btcont.name"] ?? ""
            let tags = $0.fields["btcont.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "bluetooth_continuity_depth", status: "fail", severity: "medium",
            title: "Bluetooth / Continuity proximity residual depth surface present",
            detail: "\(risky.count) Bluetooth Continuity depth marker(s) - IR surface. Path/meta only; never enables Bluetooth pairing or spoofs Continuity identities.",
            remediation: "Inventory and baseline Bluetooth Continuity depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessFontValidationDualuse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "FONTVALIDATION" || $0.eventType == "font.validation"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["fontval.risk_tags"] ?? "").lowercased()
            return tags.contains("font_surface") || !($0.fields["fontval.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["fontval.path"] ?? ""
            let name = $0.fields["fontval.name"] ?? ""
            let tags = $0.fields["fontval.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "font_validation_dualuse", status: "fail", severity: "medium",
            title: "Font validation / ATS dual-use surface surface present",
            detail: "\(risky.count) Font validation dual-use marker(s) - IR surface. Path/meta only; never installs malicious fonts or disables font validation.",
            remediation: "Inventory and baseline Font validation dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessQuicklookCacheDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "QUICKLOOKCACHE" || $0.eventType == "quicklook.cache"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["qlcache.risk_tags"] ?? "").lowercased()
            return tags.contains("quicklook_surface") || !($0.fields["qlcache.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["qlcache.path"] ?? ""
            let name = $0.fields["qlcache.name"] ?? ""
            let tags = $0.fields["qlcache.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "quicklook_cache_depth", status: "fail", severity: "medium",
            title: "QuickLook thumbnail cache residual depth surface present",
            detail: "\(risky.count) QuickLook cache depth marker(s) - IR surface. Path/meta only; never dumps QuickLook thumbnail bitmap contents as secret material.",
            remediation: "Inventory and baseline QuickLook cache depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessDnsResolverDualuse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "DNSRESOLVER" || $0.eventType == "dns.resolver"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["dnsres.risk_tags"] ?? "").lowercased()
            return tags.contains("dns_surface") || !($0.fields["dnsres.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["dnsres.path"] ?? ""
            let name = $0.fields["dnsres.name"] ?? ""
            let tags = $0.fields["dnsres.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "dns_resolver_dualuse", status: "fail", severity: "medium",
            title: "DNS resolver / mDNSResponder dual-use surface surface present",
            detail: "\(risky.count) DNS resolver dual-use marker(s) - IR surface. Path/meta only; never rewrites resolver config or poisons DNS caches.",
            remediation: "Inventory and baseline DNS resolver dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessLsQuarantineDbDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "LSQUARANTINEDB" || $0.eventType == "ls.quarantine_db"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["lsqdb.risk_tags"] ?? "").lowercased()
            return tags.contains("quarantine_db_surface") || !($0.fields["lsqdb.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["lsqdb.path"] ?? ""
            let name = $0.fields["lsqdb.name"] ?? ""
            let tags = $0.fields["lsqdb.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "ls_quarantine_db_depth", status: "fail", severity: "medium",
            title: "LaunchServices QuarantineEvents DB residual depth surface present",
            detail: "\(risky.count) LS QuarantineEvents depth marker(s) - IR surface. Path/meta only; never deletes QuarantineEvents rows or clears LS quarantine history.",
            remediation: "Inventory and baseline LS QuarantineEvents depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessPamAuthModule(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "PAMAUTHMODULE" || $0.eventType == "pam.module"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["pammod.risk_tags"] ?? "").lowercased()
            return tags.contains("pam_surface") || !($0.fields["pammod.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["pammod.path"] ?? ""
            let name = $0.fields["pammod.name"] ?? ""
            let tags = $0.fields["pammod.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "pam_auth_module", status: "fail", severity: "medium",
            title: "PAM authentication module residual surface surface present",
            detail: "\(risky.count) PAM auth module surface marker(s) - IR surface. Path/meta only; never installs PAM modules or modifies /etc/pam.d.",
            remediation: "Inventory and baseline PAM auth module surface artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessCronAtJobDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "CRONATJOB" || $0.eventType == "cron.at_job"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["cronat.risk_tags"] ?? "").lowercased()
            return tags.contains("cron_at_surface") || !($0.fields["cronat.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["cronat.path"] ?? ""
            let name = $0.fields["cronat.name"] ?? ""
            let tags = $0.fields["cronat.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "cron_at_job_depth", status: "fail", severity: "medium",
            title: "Cron / at job dual-use residual depth surface present",
            detail: "\(risky.count) Cron/at job depth marker(s) - IR surface. Path/meta only; never installs cron or at jobs outside the lab root.",
            remediation: "Inventory and baseline Cron/at job depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessNotesMetadataPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "NOTESMETADATA" || $0.eventType == "notes.metadata"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["notesmeta.risk_tags"] ?? "").lowercased()
            return tags.contains("notes_surface") || !($0.fields["notesmeta.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["notesmeta.path"] ?? ""
            let name = $0.fields["notesmeta.name"] ?? ""
            let tags = $0.fields["notesmeta.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "notes_metadata_plane", status: "fail", severity: "medium",
            title: "Notes.app metadata collection path plane surface present",
            detail: "\(risky.count) Notes metadata plane marker(s) - IR surface. Path/meta only; never reads Notes body contents or exports note secrets.",
            remediation: "Inventory and baseline Notes metadata plane artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }
    // MARK: - Wave-15 multi-plane red↔blue pair assessments
}
