import Foundation
import RootstockBlueCore
import RootstockBlueCase
extension HardeningAssessment {
    static func assessAirplayReceiverSurface(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "AIRPLAYRX" || $0.eventType == "airplay.receiver"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["airplayrx.risk_tags"] ?? "").lowercased()
            return tags.contains("airplay_surface") || !($0.fields["airplayrx.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["airplayrx.path"] ?? ""
            let name = $0.fields["airplayrx.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "airplay_receiver_surface", status: "fail", severity: "medium",
            title: "AirPlay receiver dual-use residual surface present",
            detail: "\(risky.count) AirPlay receiver dual-use marker(s) - IR surface. Path/meta only; never enables AirPlay Receiver or spoofs AirPlay targets.",
            remediation: "Inventory and baseline AirPlay receiver dual-use artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessHandoffClipboardDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "HANDOFFCB" || $0.eventType == "handoff.clipboard"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["hdoffcb.risk_tags"] ?? "").lowercased()
            return tags.contains("handoff_surface") || !($0.fields["hdoffcb.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["hdoffcb.path"] ?? ""
            let name = $0.fields["hdoffcb.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "handoff_clipboard_depth", status: "fail", severity: "medium",
            title: "Handoff / Universal Clipboard residual depth surface present",
            detail: "\(risky.count) Handoff clipboard depth marker(s) - IR surface. Path/meta only; never reads Universal Clipboard contents or forges Handoff activity.",
            remediation: "Inventory and baseline Handoff clipboard depth artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessImessagePathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "IMSGPATH" || $0.eventType == "imessage.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["imsgpath.risk_tags"] ?? "").lowercased()
            return tags.contains("imessage_surface") || !($0.fields["imsgpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["imsgpath.path"] ?? ""
            let name = $0.fields["imsgpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "imessage_path_plane", status: "fail", severity: "medium",
            title: "iMessage / Messages path collection plane surface present",
            detail: "\(risky.count) iMessage path plane marker(s) - IR surface. Path/meta only; never reads Messages database contents or exports chat transcripts.",
            remediation: "Inventory and baseline iMessage path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessFacetimeCameraSurface(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "FTCAM" || $0.eventType == "facetime.camera"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["ftcam.risk_tags"] ?? "").lowercased()
            return tags.contains("facetime_surface") || !($0.fields["ftcam.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["ftcam.path"] ?? ""
            let name = $0.fields["ftcam.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "facetime_camera_surface", status: "fail", severity: "medium",
            title: "FaceTime / camera pipeline dual-use surface surface present",
            detail: "\(risky.count) FaceTime camera dual-use marker(s) - IR surface. Path/meta only; never activates camera/mic or dumps FaceTime call history contents.",
            remediation: "Inventory and baseline FaceTime camera dual-use artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessFinderSyncExtension(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "FNDSYNC" || $0.eventType == "finder.sync_ext"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["fndsync.risk_tags"] ?? "").lowercased()
            return tags.contains("finder_sync_surface") || !($0.fields["fndsync.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["fndsync.path"] ?? ""
            let name = $0.fields["fndsync.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "finder_sync_extension", status: "fail", severity: "medium",
            title: "Finder Sync extension dual-use surface surface present",
            detail: "\(risky.count) Finder Sync dual-use marker(s) - IR surface. Path/meta only; never installs Finder Sync extensions or rewrites Finder preferences for abuse.",
            remediation: "Inventory and baseline Finder Sync dual-use artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessFileproviderDomain(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "FPDOM" || $0.eventType == "fileprovider.domain"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["fpdom.risk_tags"] ?? "").lowercased()
            return tags.contains("fileprovider_surface") || !($0.fields["fpdom.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["fpdom.path"] ?? ""
            let name = $0.fields["fpdom.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "fileprovider_domain", status: "fail", severity: "medium",
            title: "File Provider domain residual surface surface present",
            detail: "\(risky.count) File Provider domain marker(s) - IR surface. Path/meta only; never registers malicious File Provider domains or exfiltrates provider caches.",
            remediation: "Inventory and baseline File Provider domain artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessNotificationCenterDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "NOTICTR" || $0.eventType == "notification.center"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["notictr.risk_tags"] ?? "").lowercased()
            return tags.contains("notification_surface") || !($0.fields["notictr.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["notictr.path"] ?? ""
            let name = $0.fields["notictr.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "notification_center_depth", status: "fail", severity: "medium",
            title: "Notification Center residual depth surface present",
            detail: "\(risky.count) Notification Center depth marker(s) - IR surface. Path/meta only; never dumps notification body contents or forges notification payloads.",
            remediation: "Inventory and baseline Notification Center depth artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessSiriSuggestionsPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SIRISUG" || $0.eventType == "siri.suggestions"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["sirisug.risk_tags"] ?? "").lowercased()
            return tags.contains("siri_surface") || !($0.fields["sirisug.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["sirisug.path"] ?? ""
            let name = $0.fields["sirisug.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "siri_suggestions_plane", status: "fail", severity: "medium",
            title: "Siri / Suggestions data-access residual surface present",
            detail: "\(risky.count) Siri Suggestions residual marker(s) - IR surface. Path/meta only; never dumps Siri transcripts or Suggestions databases contents.",
            remediation: "Inventory and baseline Siri Suggestions residual artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessSpotlightImporterDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SPIMP" || $0.eventType == "spotlight.importer"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["spimp.risk_tags"] ?? "").lowercased()
            return tags.contains("spotlight_importer_surface") || !($0.fields["spimp.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["spimp.path"] ?? ""
            let name = $0.fields["spimp.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "spotlight_importer_depth", status: "fail", severity: "medium",
            title: "Spotlight importer residual depth surface present",
            detail: "\(risky.count) Spotlight importer depth marker(s) - IR surface. Path/meta only; never installs malicious Spotlight importers or dumps mdworker index contents.",
            remediation: "Inventory and baseline Spotlight importer depth artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessContactsPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "CTPATH" || $0.eventType == "contacts.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["ctpath.risk_tags"] ?? "").lowercased()
            return tags.contains("contacts_surface") || !($0.fields["ctpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["ctpath.path"] ?? ""
            let name = $0.fields["ctpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "contacts_path_plane", status: "fail", severity: "medium",
            title: "Contacts database path residual plane surface present",
            detail: "\(risky.count) Contacts path plane marker(s) - IR surface. Path/meta only; never exports contact cards or dumps AddressBook database contents.",
            remediation: "Inventory and baseline Contacts path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessCalendarServerPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "CALDAV" || $0.eventType == "calendar.caldav"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["caldav.risk_tags"] ?? "").lowercased()
            return tags.contains("caldav_surface") || !($0.fields["caldav.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["caldav.path"] ?? ""
            let name = $0.fields["caldav.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "calendar_server_path", status: "fail", severity: "medium",
            title: "Calendar server / CalDAV residual surface surface present",
            detail: "\(risky.count) Calendar CalDAV residual marker(s) - IR surface. Path/meta only; never reads calendar event bodies or credentials from CalDAV stores.",
            remediation: "Inventory and baseline Calendar CalDAV residual artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessRemindersCloudPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "REMCLOUD" || $0.eventType == "reminders.cloud"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["remcloud.risk_tags"] ?? "").lowercased()
            return tags.contains("reminders_cloud_surface") || !($0.fields["remcloud.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["remcloud.path"] ?? ""
            let name = $0.fields["remcloud.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "reminders_cloud_path", status: "fail", severity: "medium",
            title: "Reminders cloud path residual plane surface present",
            detail: "\(risky.count) Reminders cloud path marker(s) - IR surface. Path/meta only; never reads reminder titles/bodies or exports Reminders databases.",
            remediation: "Inventory and baseline Reminders cloud path artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }

}
