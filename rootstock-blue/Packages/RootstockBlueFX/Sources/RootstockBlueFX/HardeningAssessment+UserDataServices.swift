import Foundation
import RootstockBlueCore
import RootstockBlueCase
extension HardeningAssessment {

    static func assessMapsLocationPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "MAPSLOC" || $0.eventType == "maps.location"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["mapsloc.risk_tags"] ?? "").lowercased()
            return tags.contains("maps_location_surface") || !($0.fields["mapsloc.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["mapsloc.path"] ?? ""
            let name = $0.fields["mapsloc.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "maps_location_path", status: "fail", severity: "medium",
            title: "Maps / location services residual plane surface present",
            detail: "\(risky.count) Maps location residual marker(s) - IR surface. Path/meta only; never dumps location history or spoofs CoreLocation positions.",
            remediation: "Inventory and baseline Maps location residual artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessWeatherWidgetPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "WTHRWDG" || $0.eventType == "weather.widget"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["wthrwdg.risk_tags"] ?? "").lowercased()
            return tags.contains("weather_surface") || !($0.fields["wthrwdg.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["wthrwdg.path"] ?? ""
            let name = $0.fields["wthrwdg.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "weather_widget_path", status: "fail", severity: "medium",
            title: "Weather / widget data residual plane surface present",
            detail: "\(risky.count) Weather widget residual marker(s) - IR surface. Path/meta only; never dumps weather personalization data or widget timeline contents.",
            remediation: "Inventory and baseline Weather widget residual artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessMusicLibraryPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "MUSLIB" || $0.eventType == "music.library"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["muslib.risk_tags"] ?? "").lowercased()
            return tags.contains("music_surface") || !($0.fields["muslib.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["muslib.path"] ?? ""
            let name = $0.fields["muslib.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "music_library_path", status: "fail", severity: "medium",
            title: "Music / media library path residual surface present",
            detail: "\(risky.count) Music library path marker(s) - IR surface. Path/meta only; never exports Music library media or DRM material.",
            remediation: "Inventory and baseline Music library path artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessBooksPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "BKPATH" || $0.eventType == "books.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["bkpath.risk_tags"] ?? "").lowercased()
            return tags.contains("books_surface") || !($0.fields["bkpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["bkpath.path"] ?? ""
            let name = $0.fields["bkpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "books_path_plane", status: "fail", severity: "medium",
            title: "Books / EPUB path residual plane surface present",
            detail: "\(risky.count) Books path plane marker(s) - IR surface. Path/meta only; never extracts EPUB contents or Books annotations as bulk export.",
            remediation: "Inventory and baseline Books path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessPodcastsPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "PODPATH" || $0.eventType == "podcasts.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["podpath.risk_tags"] ?? "").lowercased()
            return tags.contains("podcasts_surface") || !($0.fields["podpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["podpath.path"] ?? ""
            let name = $0.fields["podpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "podcasts_path_plane", status: "fail", severity: "medium",
            title: "Podcasts library path residual surface present",
            detail: "\(risky.count) Podcasts path plane marker(s) - IR surface. Path/meta only; never dumps podcast episode files or account tokens.",
            remediation: "Inventory and baseline Podcasts path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessTvAppPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "TVPATH" || $0.eventType == "tv.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["tvpath.risk_tags"] ?? "").lowercased()
            return tags.contains("tv_surface") || !($0.fields["tvpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["tvpath.path"] ?? ""
            let name = $0.fields["tvpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "tv_app_path_plane", status: "fail", severity: "medium",
            title: "TV.app residual path plane surface present",
            detail: "\(risky.count) TV.app path plane marker(s) - IR surface. Path/meta only; never dumps TV.app media caches or account material.",
            remediation: "Inventory and baseline TV.app path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessHomekitPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "HKPATH" || $0.eventType == "homekit.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["hkpath.risk_tags"] ?? "").lowercased()
            return tags.contains("homekit_surface") || !($0.fields["hkpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["hkpath.path"] ?? ""
            let name = $0.fields["hkpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "homekit_path_plane", status: "fail", severity: "medium",
            title: "HomeKit residual path plane surface present",
            detail: "\(risky.count) HomeKit path plane marker(s) - IR surface. Path/meta only; never enumerates HomeKit accessory secrets or pairs devices.",
            remediation: "Inventory and baseline HomeKit path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessHealthPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "HLTHPATH" || $0.eventType == "health.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["hlthpath.risk_tags"] ?? "").lowercased()
            return tags.contains("health_surface") || !($0.fields["hlthpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["hlthpath.path"] ?? ""
            let name = $0.fields["hlthpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "health_path_plane", status: "fail", severity: "medium",
            title: "Health app residual path plane surface present",
            detail: "\(risky.count) Health path plane marker(s) - IR surface. Path/meta only; never exports HealthKit samples or medical records.",
            remediation: "Inventory and baseline Health path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessWalletPassPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "WLTPASS" || $0.eventType == "wallet.pass"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["wltpass.risk_tags"] ?? "").lowercased()
            return tags.contains("wallet_surface") || !($0.fields["wltpass.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["wltpass.path"] ?? ""
            let name = $0.fields["wltpass.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "wallet_pass_path", status: "fail", severity: "medium",
            title: "Wallet / pass residual path plane surface present",
            detail: "\(risky.count) Wallet pass path marker(s) - IR surface. Path/meta only; never dumps pass contents, payment tokens, or card data.",
            remediation: "Inventory and baseline Wallet pass path artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessFindmyPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "FMPATH" || $0.eventType == "findmy.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["fmpath.risk_tags"] ?? "").lowercased()
            return tags.contains("findmy_surface") || !($0.fields["fmpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["fmpath.path"] ?? ""
            let name = $0.fields["fmpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "findmy_path_plane", status: "fail", severity: "medium",
            title: "Find My residual path plane surface present",
            detail: "\(risky.count) Find My path plane marker(s) - IR surface. Path/meta only; never queries Find My device locations or dumps owner tokens.",
            remediation: "Inventory and baseline Find My path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessShortcutsIcloudSync(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SCICLOUD" || $0.eventType == "shortcuts.icloud"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["scicloud.risk_tags"] ?? "").lowercased()
            return tags.contains("shortcuts_icloud_surface") || !($0.fields["scicloud.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["scicloud.path"] ?? ""
            let name = $0.fields["scicloud.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "shortcuts_icloud_sync", status: "fail", severity: "medium",
            title: "Shortcuts iCloud sync residual depth surface present",
            detail: "\(risky.count) Shortcuts iCloud sync marker(s) - IR surface. Path/meta only; never executes Shortcuts or dumps iCloud-synced automation databases.",
            remediation: "Inventory and baseline Shortcuts iCloud sync artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessDevicemanagementProfile(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "MDMPROF" || $0.eventType == "mdm.profile_depth"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["mdmprof.risk_tags"] ?? "").lowercased()
            return tags.contains("device_mgmt_surface") || !($0.fields["mdmprof.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["mdmprof.path"] ?? ""
            let name = $0.fields["mdmprof.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "devicemanagement_profile", status: "fail", severity: "medium",
            title: "Device management profile residual depth surface present",
            detail: "\(risky.count) Device management profile marker(s) - IR surface. Path/meta only; never installs configuration profiles or enrolls hosts in MDM.",
            remediation: "Inventory and baseline Device management profile artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    static func assessSoftwareupdateCatalog(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SUCAT" || $0.eventType == "softwareupdate.catalog"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["sucat.risk_tags"] ?? "").lowercased()
            return tags.contains("softwareupdate_surface") || !($0.fields["sucat.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["sucat.path"] ?? ""
            let name = $0.fields["sucat.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "softwareupdate_catalog", status: "fail", severity: "medium",
            title: "Software Update catalog residual surface surface present",
            detail: "\(risky.count) Software Update catalog marker(s) - IR surface. Path/meta only; never points SUS catalogs at attacker mirrors or tampers with update plists.",
            remediation: "Inventory and baseline Software Update catalog artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }

}
