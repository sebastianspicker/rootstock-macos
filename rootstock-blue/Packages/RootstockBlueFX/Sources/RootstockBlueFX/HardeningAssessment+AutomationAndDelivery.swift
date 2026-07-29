import Foundation
import RootstockBlueCore
import RootstockBlueCase
extension HardeningAssessment {

    static func assessWeblocInetloc(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "WEBLOCINETLOC" || $0.eventType == "webloc.delivery"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["webloc.risk_tags"] ?? "").lowercased()
            return tags.contains("delivery_surface")
                || !($0.fields["webloc.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["webloc.path"] ?? ""
            let name = $0.fields["webloc.name"] ?? ""
            let tags = $0.fields["webloc.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "webloc_inetloc_delivery",
                status: "fail",
                severity: "medium",
                title: "Webloc / Internet Location file delivery surface present",
                detail: "\(risky.count) Webloc/inetloc delivery marker(s) - IR surface. Path/meta only; never crafts phishing webloc/inetloc payloads or rewrites Internet Location files.",
                remediation: "Inventory and baseline Webloc/inetloc delivery artifacts. Correlate unexpected markers with delivery or lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
                evidence: sample
            ),
        ]
    }


    static func assessMailRulesAutomation(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "MAILRULESAUTO" || $0.eventType == "mail.rules"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["mail_rules.risk_tags"] ?? "").lowercased()
            return tags.contains("rules_surface")
                || !($0.fields["mail_rules.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["mail_rules.path"] ?? ""
            let name = $0.fields["mail_rules.name"] ?? ""
            let tags = $0.fields["mail_rules.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "mail_rules_automation",
                status: "fail",
                severity: "medium",
                title: "Mail rules / Apple Mail automation persistence surface present",
                detail: "\(risky.count) Mail rules automation marker(s) - IR surface. Path/meta only; never reads Mail contents or modifies user Mail rules.",
                remediation: "Inventory and baseline Mail rules automation artifacts. Correlate unexpected markers with delivery or lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
                evidence: sample
            ),
        ]
    }


    static func assessUnifiedLogObservation(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "UNIFIEDLOGOBS" || $0.eventType == "unified_log.observation"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["ulog.risk_tags"] ?? "").lowercased()
            return tags.contains("observation_surface")
                || !($0.fields["ulog.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["ulog.path"] ?? ""
            let name = $0.fields["ulog.name"] ?? ""
            let tags = $0.fields["ulog.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "unified_log_observation",
                status: "fail",
                severity: "medium",
                title: "Unified log / logarchive observation depth surface present",
                detail: "\(risky.count) Unified log observation marker(s) - IR surface. Path/meta only; never dumps private unified-log message bodies or force-collects other users' logarchives.",
                remediation: "Inventory and baseline Unified log observation artifacts. Correlate unexpected markers with delivery or lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
                evidence: sample
            ),
        ]
    }


    static func assessDockPersistenceSurface(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "DOCKPERSIST" || $0.eventType == "dock.persistence"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["dock.risk_tags"] ?? "").lowercased()
            return tags.contains("dock_surface")
                || !($0.fields["dock.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["dock.path"] ?? ""
            let name = $0.fields["dock.name"] ?? ""
            let tags = $0.fields["dock.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "dock_persistence_surface",
                status: "fail",
                severity: "medium",
                title: "Dock persistent apps / recent items dual-use surface present",
                detail: "\(risky.count) Dock persistence dual-use marker(s) - IR surface. Path/meta only; never modifies Dock.plist or plants malicious Dock entries.",
                remediation: "Inventory and baseline Dock persistence dual-use artifacts. Correlate unexpected markers with delivery or lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
                evidence: sample
            ),
        ]
    }


    static func assessOsascriptScptDelivery(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "OSASCRIPTSCPT" || $0.eventType == "osascript.scpt"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["osa.risk_tags"] ?? "").lowercased()
            return tags.contains("scpt_surface")
                || !($0.fields["osa.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["osa.path"] ?? ""
            let name = $0.fields["osa.name"] ?? ""
            let tags = $0.fields["osa.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "osascript_scpt_delivery",
                status: "fail",
                severity: "medium",
                title: "Compiled AppleScript / OSA delivery residual surface present",
                detail: "\(risky.count) OSA/scpt delivery marker(s) - IR surface. Path/meta only; never compiles malicious .scpt payloads or executes third-party AppleScripts.",
                remediation: "Inventory and baseline OSA/scpt delivery artifacts. Correlate unexpected markers with delivery or lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
                evidence: sample
            ),
        ]
    }


    static func assessNetworkShareMount(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "NETWORKSHAREMOUNT" || $0.eventType == "network.share_mount"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["share.risk_tags"] ?? "").lowercased()
            return tags.contains("share_surface")
                || !($0.fields["share.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["share.path"] ?? ""
            let name = $0.fields["share.name"] ?? ""
            let tags = $0.fields["share.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "network_share_mount",
                status: "fail",
                severity: "medium",
                title: "Network share / SMB mount dual-use lateral surface present",
                detail: "\(risky.count) Network share mount marker(s) - IR surface. Path/meta only; never mounts attacker shares or writes credentials to NetAuth.",
                remediation: "Inventory and baseline Network share mount artifacts. Correlate unexpected markers with delivery or lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
                evidence: sample
            ),
        ]
    }
    // MARK: - Wave-13 multi-plane red↔blue pair assessments

    static func assessCalendarRemindersAutomation(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "CALENDARREMINDERS" || $0.eventType == "calendar.reminders"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["calrem.risk_tags"] ?? "").lowercased()
            return tags.contains("automation_surface") || !($0.fields["calrem.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["calrem.path"] ?? ""
            let name = $0.fields["calrem.name"] ?? ""
            let tags = $0.fields["calrem.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "calendar_reminders_automation", status: "fail", severity: "medium",
            title: "Calendar / Reminders automation lateral surface surface present",
            detail: "\(risky.count) Calendar/Reminders automation marker(s) - IR surface. Path/meta only; never reads event contents or creates malicious calendar invites.",
            remediation: "Inventory and baseline Calendar/Reminders automation artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessGatekeeperAssessmentHistory(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "GKASSESSMENTHIST" || $0.eventType == "gatekeeper.assessment"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["gkh.risk_tags"] ?? "").lowercased()
            return tags.contains("assessment_surface") || !($0.fields["gkh.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["gkh.path"] ?? ""
            let name = $0.fields["gkh.name"] ?? ""
            let tags = $0.fields["gkh.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "gatekeeper_assessment_history", status: "fail", severity: "medium",
            title: "Gatekeeper assessment / syspolicyd history depth surface present",
            detail: "\(risky.count) Gatekeeper assessment history marker(s) - IR surface. Path/meta only; never clears Gatekeeper assessments or disables syspolicyd.",
            remediation: "Inventory and baseline Gatekeeper assessment history artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessHomebrewPackageDualUse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "HOMEBREWPKG" || $0.eventType == "homebrew.package"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["brew.risk_tags"] ?? "").lowercased()
            return tags.contains("package_surface") || !($0.fields["brew.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["brew.path"] ?? ""
            let name = $0.fields["brew.name"] ?? ""
            let tags = $0.fields["brew.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "homebrew_package_dualuse", status: "fail", severity: "medium",
            title: "Homebrew / third-party package manager dual-use surface present",
            detail: "\(risky.count) Homebrew package dual-use marker(s) - IR surface. Path/meta only; never installs packages or modifies Homebrew formulae.",
            remediation: "Inventory and baseline Homebrew package dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessCupsPrintDualUse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "CUPSPRINTDUAL" || $0.eventType == "cups.print"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["cups.risk_tags"] ?? "").lowercased()
            return tags.contains("print_surface") || !($0.fields["cups.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["cups.path"] ?? ""
            let name = $0.fields["cups.name"] ?? ""
            let tags = $0.fields["cups.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "cups_print_dualuse", status: "fail", severity: "medium",
            title: "CUPS / printer dual-use residual surface surface present",
            detail: "\(risky.count) CUPS printer dual-use marker(s) - IR surface. Path/meta only; never submits print jobs or reconfigures CUPS remotely.",
            remediation: "Inventory and baseline CUPS printer dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessScreenCapturePrivacyDualUse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SCREENCAPTUREPRIV" || $0.eventType == "screencapture.privacy"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["scpriv.risk_tags"] ?? "").lowercased()
            return tags.contains("capture_surface") || !($0.fields["scpriv.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["scpriv.path"] ?? ""
            let name = $0.fields["scpriv.name"] ?? ""
            let tags = $0.fields["scpriv.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "screencapture_privacy_dualuse", status: "fail", severity: "medium",
            title: "ScreenCapture / screenshot privacy dual-use depth surface present",
            detail: "\(risky.count) ScreenCapture privacy dual-use marker(s) - IR surface. Path/meta only; never captures screens or dumps Screen Recording TCC rows.",
            remediation: "Inventory and baseline ScreenCapture privacy dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }
    // MARK: - Wave-14 multi-plane red↔blue pair assessments

}
