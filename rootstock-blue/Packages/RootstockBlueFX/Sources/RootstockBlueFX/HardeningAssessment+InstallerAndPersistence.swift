import Foundation
import RootstockBlueCore
import RootstockBlueCase
extension HardeningAssessment {
    static func assessPackageKitInstallerDesign(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "PACKAGEKITDESIGN" || $0.eventType == "packagekit.design"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["packagekit.risk_tags"] ?? "").lowercased()
            let service = $0.fields["packagekit.service_present"] == "true"
            let receipts = $0.fields["packagekit.receipt_paths"] ?? ""
            let hasReceipts = !receipts.isEmpty && receipts != "0"
            return tags.contains("design_surface")
                || (service && hasReceipts)
                || tags.contains("installer_service")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let svc = $0.fields["packagekit.service_present"] ?? "?"
            let tags = $0.fields["packagekit.risk_tags"] ?? ""
            let notes = $0.fields["packagekit.notes"] ?? ""
            return "service=\(svc) tags=\(tags) \(notes)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "packagekit_installer_design",
                status: "fail",
                severity: "medium",
                title: "PackageKit installer design surface present",
                detail: "\(risky.count) PackageKit design-surface marker(s) - installer services/receipts/plugins inventory for design-based persistence IR. Path presence only; does not build packages.",
                remediation: "Inventory InstallHistory and /var/db/receipts for unexpected package identifiers. Review Installer Plugins directories for non-Apple plugins. Correlate package_script_service / installd activity with ESF if available. Restrict ad-hoc package installs via policy; do not run untrusted pkgs. Assessment guidance only - not MDM enforcement.",
                evidence: sample
            ),
        ]
    }

    static func assessArchiveQuarantineExtractor(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "ARCHIVEEXTRACTOR" || $0.eventType == "archive.extractor"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["archive.risk_tags"] ?? "").lowercased()
            let third = $0.fields["archive.third_party"] == "true"
            return third
                || tags.contains("third_party_extractor")
                || tags.contains("quarantine_non_inherit")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let n = $0.fields["archive.extractor_name"] ?? "?"
            let p = $0.fields["archive.extractor_path"] ?? ""
            let d = $0.fields["archive.drop_hint"] ?? ""
            return "\(n) \(p) drop=\(d)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        let severity = risky.contains {
            ($0.fields["archive.risk_tags"] ?? "").contains("quarantine_non_inherit")
        } ? "high" : "medium"
        return [
            Finding(
                control: "archive_quarantine_extractor",
                status: "fail",
                severity: severity,
                title: "Third-party archive extractor (quarantine non-inherit risk)",
                detail: "\(risky.count) third-party archive extractor(s) - extracted payloads may not inherit com.apple.quarantine (Unit 42 / Jamf class research).",
                remediation: "Prefer stock Archive Utility for untrusted archives. Inventory Keka/The Unarchiver/BetterZip-class tools. After third-party extraction, re-apply quarantine or scan drop folders (Downloads/Desktop/tmp). Correlate with QuarantineEvents and Gatekeeper history. Operator assessment only - not automated quarantine strip/rewrite.",
                evidence: sample
            ),
        ]
    }

    static func assessInfoStealerPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "INFOSTEALERPATH" || $0.eventType == "stealer.path"
        }
        guard !rows.isEmpty else { return [] }
        let families = Set(rows.compactMap { $0.fields["stealer.path_family"] })
        let multiApp = families.count >= 2 || rows.contains(where: hasMultiAppStealerTag)
        let fdaAdj = rows.contains { $0.fields["stealer.fda_adjacent"] == "true" }
        let risky = rows.filter { isRiskyStealerPath($0, multiApp: multiApp) }
        guard multiApp || !risky.isEmpty else { return [] }
        let sample = rows.prefix(5).compactMap {
            let f = $0.fields["stealer.path_family"] ?? "?"
            let p = $0.fields["stealer.path"] ?? ""
            return "\(f):\(p)"
        }.joined(separator: " | ")
        // Never include secret material in evidence/detail
        let safeEvidence = sample
            .replacingOccurrences(of: "password", with: "path", options: .caseInsensitive)
        return [
            Finding(
                control: "infostealer_path_plane",
                status: "fail",
                severity: (multiApp && fdaAdj) ? "high" : "medium",
                title: "Info-stealer multi-app path plane exposed",
                detail: "\(rows.count) stealer-path marker(s) across \(families.count) family(ies) (browser/messaging/vault/wallet/sync). Path presence only - secrets not exported.",
                remediation: "Harden FDA grants; review TCC for unexpected full-disk accessors. Enable FileVault; restrict browser/password-manager backup paths. Monitor multi-family file access via EDR/ESF. Rotate credentials if stealer activity suspected. Do not dump cookies, passwords, keychains, or wallet seeds into case exports.",
                evidence: safeEvidence
            ),
        ]
    }

    static func assessTCCESFVisibilityDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "TCCESFVISIBILITY" || $0.eventType == "tcc_esf.visibility"
        }
        guard !rows.isEmpty else { return [] }
        let thinOrPartial = rows.filter(isThinOrPartialVisibility)
        guard !thinOrPartial.isEmpty else { return [] }
        let worstThin = thinOrPartial.contains(where: isThinVisibility)
        let sample = thinOrPartial.prefix(3).compactMap {
            let d = $0.fields["visibility.depth"] ?? "?"
            let t = $0.fields["visibility.tool_path"] ?? ""
            let listable = $0.fields["visibility.tcc_path_listable"] ?? "?"
            return "depth=\(d) tcc_listable=\(listable) tool=\(t)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "tcc_esf_visibility_depth",
                status: worstThin ? "fail" : "warn",
                severity: worstThin ? "high" : "medium",
                title: worstThin
                    ? "TCC/ESF operator visibility is thin"
                    : "TCC/ESF operator visibility is only partial",
                detail: "\(thinOrPartial.count) visibility-depth marker(s) indicate limited TCC path listability and/or missing ESF/eslogger tooling - sensor gap for grant and process telemetry IR.",
                remediation: "Ensure IR tooling can list TCC.db paths (with proper authorization). Deploy ESF-capable sensor or eslogger where ROE allows. Document visibility depth in IR runbooks. Prefer EDR that surfaces TCC grant changes. Do not dump raw TCC.db rows into unsecured exports; assess depth only.",
                evidence: sample
            ),
        ]
    }

    // MARK: - Wave-11 multi-plane red↔blue pair assessments

    static func assessURLSchemeHandler(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "URLSCHEMEHANDLER" || $0.eventType == "url_scheme.handler"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["url_scheme.risk_tags"] ?? "").lowercased()
            return tags.contains("handler_surface")
                || tags.contains("third_party_handler")
                || tags.contains("custom_scheme")
                || !($0.fields["url_scheme.handler_path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["url_scheme.handler_path"] ?? ""
            let scheme = $0.fields["url_scheme.scheme"] ?? ""
            let tags = $0.fields["url_scheme.risk_tags"] ?? ""
            return "scheme=\(scheme) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "url_scheme_handler",
                status: "fail",
                severity: "medium",
                title: "URL scheme / document-handler surface present",
                detail: "\(risky.count) URL scheme/document-handler marker(s) - LaunchServices / custom scheme delivery IR surface. Path presence only; does not register schemes.",
                remediation: "Inventory non-default CFBundleURLTypes and LaunchServices handlers after software installs. Restrict untrusted apps that register custom URL schemes via MDM allowlists. Correlate handler changes with phishing delivery. Do not rewrite handlers from IR tooling without change control.",
                evidence: sample
            ),
        ]
    }

    static func assessLaunchdOverrideDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "LAUNCHDOVERRIDEDEPTH" || $0.eventType == "launchd.override_depth"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter(isRiskyLaunchdOverride)
        guard !risky.isEmpty else { return [] }
        let securityHit = risky.contains(where: hasSecurityProductDisableHint)
        let sample = risky.prefix(4).compactMap {
            let label = $0.fields["launchd_depth.label"] ?? "?"
            let path = $0.fields["launchd_depth.override_path"] ?? ""
            return "\(label) @ \(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "launchd_override_depth",
                status: "fail",
                severity: securityHit ? "high" : "medium",
                title: securityHit
                    ? "Launchd override depth shows security-product disable hints"
                    : "Launchd disabled / override depth surface present",
                detail: "\(risky.count) launchd override-depth marker(s) - disabled.plist / overrides inventory for defense-evasion IR. Does not disable jobs.",
                remediation: "Audit /var/db/com.apple.xpc.launchd/disabled*.plist for unexpected Santa/Falcon/osquery/Jamf labels. Alert on launchctl disable of security products via ESF/MDM. Restore disabled security agents via approved change control. Assessment guidance only - not an unload toolkit.",
                evidence: sample
            ),
        ]
    }

    static func assessBrowserExtensionDualUse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "BROWSEREXTDUALUSE" || $0.eventType == "browser.extension_dualuse"
        }
        guard !rows.isEmpty else { return [] }
        let browsers = Set(rows.compactMap { $0.fields["ext_dualuse.browser"] })
        let risky = rows.filter(isRiskyBrowserExtension)
        guard !risky.isEmpty || browsers.count >= 2 else { return [] }
        let sample = rows.prefix(5).compactMap {
            let browser = $0.fields["ext_dualuse.browser"] ?? "?"
            let path = $0.fields["ext_dualuse.path"] ?? ""
            let extID = $0.fields["ext_dualuse.extension_id"] ?? ""
            return "\(browser):\(extID.isEmpty ? path : extID)"
        }.joined(separator: " | ")
        let safe = sample.replacingOccurrences(of: "password", with: "path", options: .caseInsensitive)
        let broad = risky.contains(where: hasBroadExtensionPermissions)
        return [
            Finding(
                control: "browser_extension_dualuse",
                status: "fail",
                severity: (browsers.count >= 2 || broad) ? "high" : "medium",
                title: "Browser extension dual-use persistence/collection plane",
                detail: "\(rows.count) browser-extension dual-use marker(s) across \(browsers.count) browser(s). Path/meta only - secrets not exported.",
                remediation: "Enforce enterprise extension allowlists via MDM/Chrome enterprise policy. Remove unapproved extensions; monitor Secure Preferences changes. Correlate extension installs with phishing. Do not export extension storage, cookies, or tokens into case packages.",
                evidence: safe
            ),
        ]
    }

    static func assessShortcutsAppIntents(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SHORTCUTSAPPINTENTS" || $0.eventType == "shortcuts.automation"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter(isRiskyShortcut)
        guard !risky.isEmpty else { return [] }
        let scripting = risky.contains(where: hasScriptingShortcutAction)
        let sample = risky.prefix(4).compactMap {
            let name = $0.fields["shortcuts.name"] ?? "?"
            let path = $0.fields["shortcuts.path"] ?? ""
            return "\(name) \(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "shortcuts_app_intents",
                status: "fail",
                severity: scripting ? "high" : "medium",
                title: scripting
                    ? "Shortcuts / App Intents automation with scripting risk"
                    : "Shortcuts / App Intents automation surface present",
                detail: "\(risky.count) Shortcuts/App Intents marker(s) - automation lateral IR surface. Does not execute shortcuts.",
                remediation: "Review personal automations and shared Shortcuts for shell/scripting actions. Restrict Shortcuts network/scripting via MDM where available. Correlate Shortcuts database changes with delivery timelines. Do not run untrusted Shortcuts during IR without sandboxing.",
                evidence: sample
            ),
        ]
    }
    // MARK: - Wave-12 multi-plane red↔blue pair assessments
    private static func hasMultiAppStealerTag(_ event: EventEnvelope) -> Bool { containsAny((event.fields["stealer.risk_tags"] ?? "").lowercased(), terms: ["multi_app_collection"]) }
    private static func isRiskyStealerPath(_ event: EventEnvelope, multiApp: Bool) -> Bool {
        let tags = (event.fields["stealer.risk_tags"] ?? "").lowercased()
        return [containsAny(tags, terms: ["multi_app_collection"]), event.fields["stealer.fda_adjacent"] == "true", tags.split(separator: ",").filter { !$0.isEmpty }.count >= 2, multiApp].contains(true)
    }
    private static func isThinOrPartialVisibility(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return [(fields["visibility.depth"] ?? "").lowercased() == "thin", containsAny((fields["visibility.risk_tags"] ?? "").lowercased(), terms: ["thin_visibility", "sensor_gap_adjacent"]), (fields["visibility.depth"] ?? "").lowercased() == "partial"].contains(true)
    }
    private static func isThinVisibility(_ event: EventEnvelope) -> Bool { [(event.fields["visibility.depth"] ?? "").lowercased() == "thin", containsAny((event.fields["visibility.risk_tags"] ?? "").lowercased(), terms: ["thin_visibility"])].contains(true) }
    private static func isRiskyLaunchdOverride(_ event: EventEnvelope) -> Bool { [event.fields["launchd_depth.security_product_hint"] == "true", containsAny((event.fields["launchd_depth.risk_tags"] ?? "").lowercased(), terms: ["security_product_disabled", "override_depth"])].contains(true) }
    private static func hasSecurityProductDisableHint(_ event: EventEnvelope) -> Bool { [event.fields["launchd_depth.security_product_hint"] == "true", containsAny(event.fields["launchd_depth.risk_tags"] ?? "", terms: ["security_product_disabled"])].contains(true) }
    private static func isRiskyBrowserExtension(_ event: EventEnvelope) -> Bool { containsAny((event.fields["ext_dualuse.risk_tags"] ?? "").lowercased(), terms: ["dual_use_surface", "broad_permissions", "fda_adjacent"]) }
    private static func hasBroadExtensionPermissions(_ event: EventEnvelope) -> Bool { containsAny(event.fields["ext_dualuse.risk_tags"] ?? "", terms: ["broad_permissions"]) }
    private static func isRiskyShortcut(_ event: EventEnvelope) -> Bool { containsAny((event.fields["shortcuts.risk_tags"] ?? "").lowercased(), terms: ["automation_surface", "scripting_action", "remote_adjacent"]) || !(event.fields["shortcuts.path"] ?? "").isEmpty }
    private static func hasScriptingShortcutAction(_ event: EventEnvelope) -> Bool { containsAny(event.fields["shortcuts.risk_tags"] ?? "", terms: ["scripting_action"]) }
}
