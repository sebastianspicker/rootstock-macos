import Foundation
import RootstockBlueCore
import RootstockBlueCase
extension HardeningAssessment {

    static func assessTrashSensitive(_ events: [EventEnvelope]) -> [Finding] {
        let trash = events.filter {
            $0.sourcePlugin == "TRASH" || $0.eventType == "filesystem.trash"
        }
        guard !trash.isEmpty else { return [] }
        let risky = trash.filter(isRiskyTrashItem)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let n = $0.fields["trash.filename"] ?? "?"
            let o = $0.fields["trash.original_path"] ?? ""
            return o.isEmpty ? n : "\(n)←\(o)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "trash_sensitive_artifact",
                status: "fail",
                severity: "high",
                title: "Sensitive or suspicious artifacts in Trash",
                detail: "\(risky.count) trash item(s) with credential/executable/suspicious risk tags (of \(trash.count) inventoried).",
                remediation: "Preserve Trash contents before emptying (custody). Recover credential material under change control; do not re-export private keys into SIEM. Investigate deleted payloads/executables against persistence inventory and browser downloads.",
                evidence: sample
            ),
        ]
    }

    static func assessSpotlightSensitive(_ events: [EventEnvelope]) -> [Finding] {
        let items = events.filter {
            $0.sourcePlugin == "SPOTLIGHT" || $0.eventType == "filesystem.spotlight"
        }
        guard !items.isEmpty else { return [] }
        let risky = items.filter(isRiskySpotlightItem)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            $0.fields["spotlight.path"] ?? $0.fields["spotlight.display_name"]
        }.joined(separator: " | ")
        return [
            Finding(
                control: "spotlight_sensitive_index",
                status: "fail",
                severity: "medium",
                title: "Sensitive paths present in Spotlight inventory",
                detail: "\(risky.count) Spotlight index row(s) reference credential-like or suspicious paths.",
                remediation: "Correlate with Trash/QuickLook/DocumentRevisions for recovery. Restrict Spotlight privacy exclusions for highly sensitive volumes via MDM where policy allows. Investigate unexpected DMG/payload paths in Downloads.",
                evidence: sample
            ),
        ]
    }

    static func assessFirefoxSuspiciousDownload(_ events: [EventEnvelope]) -> [Finding] {
        let firefox = events.filter { $0.sourcePlugin == "FIREFOX" }
        guard !firefox.isEmpty else { return [] }
        let risky = firefox.filter(isRiskyFirefoxDownload)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let u = $0.fields["browser.url"] ?? ""
            let p = $0.fields["browser.download_path"] ?? ""
            return p.isEmpty ? u : "\(u)→\(p)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "firefox_suspicious_download",
                status: "fail",
                severity: "high",
                title: "Suspicious Firefox download or evil-domain visit",
                detail: "\(risky.count) Firefox browser event(s) with evil_domain/script_download/tmp risk (of \(firefox.count) Firefox rows).",
                remediation: "Quarantine downloaded scripts; correlate with Trash, QuarantineEvents, and persistence. Block evil.example-class domains via DNS/EDR. Prefer Firefox enterprise policies for download restrictions.",
                evidence: sample
            ),
        ]
    }

    static func assessNotificationSensitive(_ events: [EventEnvelope]) -> [Finding] {
        let notifs = events.filter {
            $0.sourcePlugin == "NOTIFICATIONS" || $0.eventType == "notification.delivered"
        }
        guard !notifs.isEmpty else { return [] }
        let risky = notifs.filter(isRiskyNotification)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let a = $0.fields["notif.app_id"] ?? "?"
            let t = $0.fields["notif.title_marker"] ?? ""
            return "\(a): \(t)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "notification_sensitive_marker",
                status: "fail",
                severity: "medium",
                title: "Security-sensitive or suspicious Notification Center markers",
                detail: "\(risky.count) notification metadata row(s) from suspicious apps or security-sensitive titles. Full notification bodies are not exported (privacy non-goal).",
                remediation: "Inventory the delivering app bundle; remove unauthorized apps that post security-like notifications. Correlate with SAVEDSTATE/SCREENTIME for the same bundle_id. Do not dump full notification bodies into SIEM by default.",
                evidence: sample
            ),
        ]
    }

    static func assessQuickLookSensitive(_ events: [EventEnvelope]) -> [Finding] {
        let ql = events.filter {
            $0.sourcePlugin == "QUICKLOOK" || $0.eventType == "filesystem.quicklook"
        }
        guard !ql.isEmpty else { return [] }
        let risky = ql.filter(isRiskyQuickLookItem)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap { $0.fields["ql.path"] }.joined(separator: " | ")
        return [
            Finding(
                control: "quicklook_sensitive_cache",
                status: "fail",
                severity: "medium",
                title: "Sensitive paths in QuickLook thumbnail cache",
                detail: "\(risky.count) QuickLook cache row(s) reference credential-like or suspicious files (files may have been previewed even if later deleted).",
                remediation: "Preserve QL cache before wipe. Correlate with Trash/Spotlight/DocumentRevisions. Investigate who previewed credential files; rotate secrets if exfil is suspected.",
                evidence: sample
            ),
        ]
    }

    static func assessScreenTimeSuspicious(_ events: [EventEnvelope]) -> [Finding] {
        let st = events.filter {
            $0.sourcePlugin == "SCREENTIME"
                && ($0.eventType == "pol.screentime" || $0.fields["screentime.app_id"] != nil)
        }
        guard !st.isEmpty else { return [] }
        let risky = st.filter(isRiskyScreenTimeItem)
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let a = $0.fields["screentime.app_id"] ?? "?"
            let u = $0.fields["screentime.usage_seconds"] ?? ""
            return "\(a) usage=\(u)s"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "screentime_suspicious_app",
                status: "fail",
                severity: "high",
                title: "Suspicious app usage in Screen Time markers",
                detail: "\(risky.count) Screen Time app row(s) with suspicious_app/tmp_path risk. Metadata only - no private activity content dump.",
                remediation: "Remove unauthorized bundles under /tmp. Correlate with SAVEDSTATE, NOTIFICATIONS, and persistence inventory for the same bundle_id. Enforce app allowlisting (Santa) for non-App-Store executables.",
                evidence: sample
            ),
        ]
    }

    static func assessICloudDesktopDocuments(_ events: [EventEnvelope]) -> [Finding] {
        let cloud = events.filter {
            $0.sourcePlugin == "ICLOUD" || $0.eventType == "cloud.sync_posture"
        }
        guard !cloud.isEmpty else { return [] }
        let risky = cloud.filter {
            $0.fields["icloud.desktop_documents_sync"] == "true"
                || ($0.fields["icloud.risk_tags"] ?? "").contains("desktop_documents_sync")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(2).compactMap {
            let u = $0.fields["icloud.signed_in_user"] ?? ""
            let d = $0.fields["icloud.drive_enabled"] ?? ""
            return "user=\(u) drive=\(d) desktop_docs=true"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "icloud_desktop_documents_sync",
                status: "fail",
                severity: "medium",
                title: "iCloud Desktop & Documents sync enabled",
                detail: "iCloud Desktop and Documents folder sync is enabled - potential bulk data staging/exfil path and dual-device evidence split.",
                remediation: "For high-sensitivity hosts, disable Desktop & Documents via MDM configuration profile. Inventory CloudDocs leftovers; correlate with Drive enablement and recent large uploads. Document account presence without exporting full Apple ID secrets.",
                evidence: sample
            ),
        ]
    }

    static func assessSavedStateSuspicious(_ events: [EventEnvelope]) -> [Finding] {
        let states = events.filter {
            $0.sourcePlugin == "SAVEDSTATE" || $0.eventType == "app.saved_state"
        }
        guard !states.isEmpty else { return [] }
        let risky = states.filter {
            let tags = ($0.fields["savedstate.risk_tags"] ?? "").lowercased()
            let bid = ($0.fields["savedstate.bundle_id"] ?? "").lowercased()
            let app = ($0.fields["savedstate.app_path"] ?? "").lowercased()
            return tags.contains("suspicious") || tags.contains("tmp_path")
                || bid.contains("evil") || bid.contains("implant")
                || app.contains("/tmp/")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            $0.fields["savedstate.bundle_id"] ?? $0.fields["savedstate.path"]
        }.joined(separator: " | ")
        return [
            Finding(
                control: "saved_state_suspicious_app",
                status: "fail",
                severity: "medium",
                title: "Suspicious Saved Application State",
                detail: "\(risky.count) Saved Application State row(s) for suspicious/tmp-backed apps.",
                remediation: "Remove unauthorized .savedState directories after custody copy. Correlate bundle_id with Screen Time, notifications, and persistence. Block tmp-path app execution via Santa/MDM.",
                evidence: sample
            ),
        ]
    }

    private static func isRiskyTrashItem(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return containsAny((fields["trash.risk_tags"] ?? "").lowercased(), terms: ["credential", "sensitive", "executable", "suspicious"])
            || containsAny((fields["trash.filename"] ?? "").lowercased(), terms: ["id_rsa", "evil", "payload"])
            || containsAny((fields["trash.original_path"] ?? "").lowercased(), terms: [".ssh/", "password"])
    }

    private static func isRiskySpotlightItem(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return containsAny((fields["spotlight.risk_tags"] ?? "").lowercased(), terms: ["sensitive", "credential", "suspicious"])
            || containsAny((fields["spotlight.path"] ?? "").lowercased(), terms: ["password", "evil"])
            || containsAny((fields["spotlight.display_name"] ?? "").lowercased(), terms: ["password", "payload"])
    }

    private static func isRiskyFirefoxDownload(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        let path = (fields["browser.download_path"] ?? "").lowercased()
        return containsAny((fields["browser.risk_tags"] ?? "").lowercased(), terms: ["evil", "script_download", "tmp_path"])
            || containsAny((fields["browser.url"] ?? "").lowercased(), terms: ["evil"])
            || containsAny(path, terms: ["payload", "evil"])
            || [".sh", ".command"].contains(where: path.hasSuffix)
    }

    private static func isRiskyNotification(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return containsAny((fields["notif.risk_tags"] ?? "").lowercased(), terms: ["suspicious", "security_sensitive"])
            || containsAny((fields["notif.app_id"] ?? "").lowercased(), terms: ["evil", "implant"])
            || containsAny((fields["notif.title_marker"] ?? "").lowercased(), terms: ["remote access", "password"])
    }

    private static func isRiskyQuickLookItem(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return containsAny((fields["ql.risk_tags"] ?? "").lowercased(), terms: ["sensitive", "credential", "suspicious"])
            || containsAny((fields["ql.path"] ?? "").lowercased(), terms: ["password", "secret", "evil"])
    }

    private static func isRiskyScreenTimeItem(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return containsAny((fields["screentime.risk_tags"] ?? "").lowercased(), terms: ["suspicious", "tmp_path"])
            || containsAny((fields["screentime.app_id"] ?? "").lowercased(), terms: ["evil", "implant"])
            || containsAny((fields["screentime.bundle_path"] ?? "").lowercased(), terms: ["/tmp/"])
    }
}
