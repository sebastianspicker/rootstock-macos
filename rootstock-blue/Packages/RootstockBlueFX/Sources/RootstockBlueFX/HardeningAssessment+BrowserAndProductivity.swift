import Foundation
import RootstockBlueCore
import RootstockBlueCase
extension HardeningAssessment {
    // MARK: - Wave-7 assessments

    static func assessCookieEvilDomain(_ events: [EventEnvelope]) -> [Finding] {
        let cookies = events.filter {
            $0.sourcePlugin == "COOKIES" || $0.eventType == "browser.cookie"
        }
        guard !cookies.isEmpty else { return [] }
        let risky = cookies.filter(isRiskyCookie)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let d = $0.fields["cookie.domain"] ?? "?"
            let n = $0.fields["cookie.name_marker"] ?? ""
            return n.isEmpty ? d : "\(d)/\(n)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "cookie_evil_domain",
                status: "fail",
                severity: "high",
                title: "Browser cookies for evil or suspicious domains",
                detail: "\(risky.count) cookie domain row(s) with evil_domain/suspicious_domain risk (of \(cookies.count) inventoried). Raw cookie values are not exported.",
                remediation: "Clear browser cookies for listed domains under custody. Force re-auth for enterprise SSO sessions. Block evil.example-class domains via DNS/EDR. Correlate with COOKIES + BOOKMARKS + browser history. Do not export raw session cookie values into SIEM.",
                evidence: sample
            ),
        ]
    }

    static func assessBookmarkEvilDomain(_ events: [EventEnvelope]) -> [Finding] {
        let bookmarks = events.filter {
            $0.sourcePlugin == "BOOKMARKS" || $0.eventType == "browser.bookmark"
        }
        guard !bookmarks.isEmpty else { return [] }
        let risky = bookmarks.filter(isRiskyBookmark)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            $0.fields["bookmark.url"] ?? $0.fields["bookmark.title"]
        }.joined(separator: " | ")
        return [
            Finding(
                control: "bookmark_evil_domain",
                status: "fail",
                severity: "medium",
                title: "Browser bookmarks pointing to evil or suspicious URLs",
                detail: "\(risky.count) bookmark(s) with evil_domain/suspicious/script risk tags.",
                remediation: "Remove malicious bookmarks; educate user on phishing bookmarking. Correlate with cookie domains and download history. Block listed domains fleet-wide.",
                evidence: sample
            ),
        ]
    }

    static func assessOfficeMRUSensitive(_ events: [EventEnvelope]) -> [Finding] {
        let mru = events.filter {
            $0.sourcePlugin == "OFFICEMRU" || $0.eventType == "mru.office"
        }
        guard !mru.isEmpty else { return [] }
        let risky = mru.filter(isRiskyOfficeMRU)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let a = $0.fields["office.app"] ?? "?"
            let p = $0.fields["office.path"] ?? $0.fields["office.title"] ?? ""
            return "\(a): \(p)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "office_mru_sensitive",
                status: "fail",
                severity: "medium",
                title: "Sensitive or suspicious Office/collaboration MRU entries",
                detail: "\(risky.count) Office/Teams/Slack MRU row(s) reference sensitive, tmp, or suspicious documents.",
                remediation: "Preserve MRU lists before wipe. Investigate tmp-path and credential-named documents. Correlate with cloud sync (CLOUDSYNC/ICLOUD) and print jobs. Restrict Office macro policies via MDM.",
                evidence: sample
            ),
        ]
    }

    static func assessPrintSensitiveJob(_ events: [EventEnvelope]) -> [Finding] {
        let jobs = events.filter {
            $0.sourcePlugin == "PRINTJOBS" || $0.eventType == "print.job"
        }
        guard !jobs.isEmpty else { return [] }
        let risky = jobs.filter(isRiskyPrintJob)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let d = $0.fields["print.document"] ?? "?"
            let p = $0.fields["print.printer"] ?? ""
            return p.isEmpty ? d : "\(d)@\(p)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "print_sensitive_job",
                status: "fail",
                severity: "medium",
                title: "Sensitive documents in print job history",
                detail: "\(risky.count) print job(s) with sensitive/suspicious document names (of \(jobs.count) inventoried).",
                remediation: "Preserve CUPS job history. Interview user and correlate with physical access. Disable unnecessary remote printers. Treat payroll/credential prints as potential data leakage.",
                evidence: sample
            ),
        ]
    }

    static func assessNotesSensitiveMarker(_ events: [EventEnvelope]) -> [Finding] {
        let notes = events.filter {
            $0.sourcePlugin == "NOTES" || $0.eventType == "notes.metadata"
        }
        guard !notes.isEmpty else { return [] }
        let risky = notes.filter(isRiskyNotesMarker)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            $0.fields["notes.title_marker"]
        }.joined(separator: " | ")
        return [
            Finding(
                control: "notes_sensitive_marker",
                status: "fail",
                severity: "medium",
                title: "Sensitive title markers in Apple Notes metadata",
                detail: "\(risky.count) Notes metadata row(s) with credential-like titles. Full note bodies are not exported (privacy non-goal).",
                remediation: "Acquire full Notes content only under legal authority with a dedicated tool. Rotate any credentials implied by titles. Prefer password managers over Notes for secrets. Do not dump note bodies into SIEM by default.",
                evidence: sample
            ),
        ]
    }

    static func assessIDeviceBackupUnencrypted(_ events: [EventEnvelope]) -> [Finding] {
        let backups = events.filter {
            $0.sourcePlugin == "IDEVICEBACKUP" || $0.eventType == "backup.idevice"
        }
        guard !backups.isEmpty else { return [] }
        let risky = backups.filter {
            $0.fields["backup.encrypted"] == "false"
                || ($0.fields["backup.risk_tags"] ?? "").contains("unencrypted_backup")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let n = $0.fields["backup.device_name"] ?? "?"
            let e = $0.fields["backup.encrypted"] ?? "?"
            return "\(n) encrypted=\(e)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "idevice_backup_unencrypted",
                status: "fail",
                severity: "high",
                title: "Unencrypted iDevice backup present",
                detail: "\(risky.count) iDevice backup marker(s) report encryption disabled - full device content may be readable offline.",
                remediation: "Enable encrypted backups (Finder/iTunes) with a strong password under custody. Inventory backup paths; restrict access ACLs. For IR, image encrypted backups with consent rather than leaving unencrypted copies on disk.",
                evidence: sample
            ),
        ]
    }

    static func assessMSRDCRemoteConnection(_ events: [EventEnvelope]) -> [Finding] {
        let rdp = events.filter {
            $0.sourcePlugin == "MSRDC" || $0.eventType == "remote.rdp_connection"
        }
        guard !rdp.isEmpty else { return [] }
        let risky = rdp.filter(isRiskyRDPConnection)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let h = $0.fields["rdp.host"] ?? "?"
            let u = $0.fields["rdp.user"] ?? ""
            return u.isEmpty ? h : "\(u)@\(h)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "msrdc_remote_connection",
                status: "fail",
                severity: "medium",
                title: "Remote desktop client connection history present",
                detail: "\(risky.count) MSRDC/RDP client connection(s) inventoried - lateral movement / remote-access residue.",
                remediation: "Validate each host against asset inventory. Remove unauthorized RDP clients (MSRDC). Correlate with ARD/SSH remote access posture. Block unexpected egress to :3389 via host firewall/MDM.",
                evidence: sample
            ),
        ]
    }

    static func assessCloudSyncExfilProvider(_ events: [EventEnvelope]) -> [Finding] {
        let cloud = events.filter {
            $0.sourcePlugin == "CLOUDSYNC" || $0.eventType == "cloud.provider_sync"
        }
        guard !cloud.isEmpty else { return [] }
        let risky = cloud.filter {
            let tags = ($0.fields["cloud.risk_tags"] ?? "").lowercased()
            let enabled = $0.fields["cloud.sync_enabled"] == "true"
            let provider = ($0.fields["cloud.provider"] ?? "").lowercased()
            return enabled
                && (tags.contains("exfil_capable") || tags.contains("sync_enabled")
                    || ["dropbox", "onedrive", "google_drive", "gdrive", "box", "mega"]
                    .contains(provider))
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let p = $0.fields["cloud.provider"] ?? "?"
            let a = $0.fields["cloud.account_marker"] ?? ""
            let f = $0.fields["cloud.folder_path"] ?? ""
            return "\(p) \(a) \(f)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "cloudsync_exfil_provider",
                status: "fail",
                severity: "medium",
                title: "Third-party cloud sync provider enabled",
                detail: "\(risky.count) multi-provider cloud sync row(s) enabled (Dropbox/OneDrive/GDrive/Box class) - bulk staging/exfil surface beyond iCloud.",
                remediation: "Inventory authorized cloud providers via MDM allowlist. Disable unauthorized Dropbox/OneDrive/GDrive/Box clients. Correlate with ICLOUD Desktop&Documents and Office MRU cloud docs. Monitor large uploads via EDR/NE.",
                evidence: sample
            ),
        ]
    }

    // MARK: - Wave-8 residual red↔blue pair assessments

    private static func isRiskyCookie(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return containsAny((fields["cookie.risk_tags"] ?? "").lowercased(), terms: ["evil_domain", "suspicious_domain"])
            || containsAny((fields["cookie.domain"] ?? "").lowercased(), terms: ["evil", "malware", "c2."])
    }

    private static func isRiskyBookmark(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        let url = (fields["bookmark.url"] ?? "").lowercased()
        return containsAny((fields["bookmark.risk_tags"] ?? "").lowercased(), terms: ["evil_domain", "suspicious_domain", "script_bookmark"])
            || containsAny(url, terms: ["evil", "malware"])
            || url.hasPrefix("javascript:")
    }

    private static func isRiskyOfficeMRU(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return containsAny((fields["office.risk_tags"] ?? "").lowercased(), terms: ["sensitive", "tmp_path", "suspicious"])
            || containsAny((fields["office.path"] ?? "").lowercased(), terms: ["/tmp/", "password", "evil"])
            || containsAny((fields["office.title"] ?? "").lowercased(), terms: ["password", "secret"])
    }

    private static func isRiskyPrintJob(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return containsAny((fields["print.risk_tags"] ?? "").lowercased(), terms: ["sensitive", "suspicious"])
            || containsAny((fields["print.document"] ?? "").lowercased(), terms: ["password", "secret", "payroll", "credential", "evil"])
    }

    private static func isRiskyNotesMarker(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return containsAny((fields["notes.risk_tags"] ?? "").lowercased(), terms: ["sensitive", "suspicious"])
            || containsAny((fields["notes.title_marker"] ?? "").lowercased(), terms: ["password", "credential", "secret", "api key"])
    }

    private static func isRiskyRDPConnection(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        let host = (fields["rdp.host"] ?? "").lowercased()
        return containsAny((fields["rdp.risk_tags"] ?? "").lowercased(), terms: ["remote_connection", "suspicious_host", "external_host"])
            || containsAny(host, terms: ["evil", "c2"])
            || !host.isEmpty
    }
}
