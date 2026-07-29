import Foundation
import RootstockBlueCore
import RootstockBlueCase
extension HardeningAssessment {

    static func assessPrivHelpers(_ events: [EventEnvelope]) -> [Finding] {
        let helpers = events.filter {
            $0.sourcePlugin == "PRIVHELPERS" || $0.fields["persistence.kind"] == "privileged_helper"
        }
        guard !helpers.isEmpty else { return [] }
        let risky = helpers.filter(isRiskyPrivilegedHelper)
        if !risky.isEmpty {
            let labels = risky.prefix(5).compactMap {
                $0.fields["privhelper.label"] ?? $0.fields["persistence.label"]
            }.joined(separator: ", ")
            return [
                Finding(
                    control: "privileged_helper_unknown",
                    status: "fail",
                    severity: "high",
                    title: "Unknown or risky privileged helper tools",
                    detail: "\(risky.count) privileged helper(s) with orphan/unknown-team/tmp risk tags (of \(helpers.count) total).",
                    remediation: "Inventory /Library/PrivilegedHelperTools and paired LaunchDaemons. Remove orphaned helpers after validating no required app depends on them. Prefer vendors that uninstall helpers cleanly.",
                    evidence: labels
                ),
            ]
        }
        return [
            Finding(
                control: "privileged_helper_unknown",
                status: "warn",
                severity: "low",
                title: "Privileged helper tools present",
                detail: "\(helpers.count) privileged helper(s) inventoried - review for legitimacy.",
                remediation: "Baseline known SMJobBless helpers; alert on new labels/TeamIDs.",
                evidence: helpers.prefix(3).compactMap { $0.fields["persistence.label"] }.joined(separator: ", ")
            ),
        ]
    }

    static func assessFolderActions(_ events: [EventEnvelope]) -> [Finding] {
        let actions = events.filter {
            $0.sourcePlugin == "FOLDERACTIONS" || $0.fields["persistence.kind"] == "folder_action"
        }
        guard !actions.isEmpty else { return [] }
        let risky = actions.filter {
            let tags = ($0.fields["persistence.risk_tags"] ?? $0.fields["folder_action.risk_tags"] ?? "").lowercased()
            return tags.contains("do_shell_script") || tags.contains("downloads_watch")
                || tags.contains("tmp_payload") || tags.contains("network_fetch")
                || tags.contains("desktop_watch")
        }
        if !risky.isEmpty {
            return [
                Finding(
                    control: "folder_action_risky",
                    status: "fail",
                    severity: "high",
                    title: "Risky Folder Action / Automator workflow",
                    detail: "\(risky.count) folder action(s) with LotL or high-risk watch paths.",
                    remediation: "Review Folder Actions Setup; remove unknown scripts under ~/Library/Scripts/Folder Action Scripts and workflows under ~/Library/Workflows/Applications/Folder Actions. Investigate Automation TCC grants.",
                    evidence: risky.prefix(3).compactMap {
                        $0.fields["folder_action.script_path"] ?? $0.fields["persistence.command"]
                    }.joined(separator: " | ")
                ),
            ]
        }
        return [
            Finding(
                control: "folder_action_risky",
                status: "warn",
                severity: "low",
                title: "Folder Actions inventory non-empty",
                detail: "\(actions.count) folder action(s) present - review for legitimacy.",
                remediation: "Confirm actions are organization-approved; otherwise remove.",
                evidence: ""
            ),
        ]
    }

    static func assessLoginHooks(_ events: [EventEnvelope]) -> [Finding] {
        let hooks = events.filter {
            $0.sourcePlugin == "LOGINHOOKS"
                || $0.fields["persistence.kind"] == "login_hook"
                || $0.fields["persistence.kind"] == "logout_hook"
        }
        guard !hooks.isEmpty else { return [] }
        let paths = hooks.compactMap { $0.fields["loginwindow.script_path"] ?? $0.fields["persistence.command"] }
        return [
            Finding(
                control: "login_hook_present",
                status: "fail",
                severity: "high",
                title: "Login/Logout hook configured",
                detail: "loginwindow LoginHook/LogoutHook is set (\(hooks.count) hook(s)) - root-context script at interactive boundary (T1037.002).",
                remediation: "Remove with sudo defaults delete com.apple.loginwindow LoginHook (and LogoutHook). Replace legitimate needs with LaunchDaemon/Agent or MDM. Preserve script path and hash for IR before deletion.",
                evidence: paths.prefix(3).joined(separator: " | ")
            ),
        ]
    }

    static func assessAccountPosture(_ events: [EventEnvelope]) -> [Finding] {
        var findings: [Finding] = []
        let accounts = events.filter(isAccountPostureEvent)

        let guestOn = accounts.contains(where: isGuestAccountEnabled)
        if guestOn {
            findings.append(Finding(
                control: "guest_account",
                status: "fail",
                severity: "medium",
                title: "Guest account enabled",
                detail: "Guest User login appears enabled.",
                remediation: "Disable Guest User in Users & Groups / via MDM. Guest sessions leave residual risk on shared or stolen devices.",
                evidence: "guest_account_enabled"
            ))
        }

        let autoOn = accounts.contains(where: isAutoLoginEnabled)
        if autoOn {
            let user = accounts.compactMap { $0.fields["account.auto_login_user"] ?? $0.fields[FieldTaxonomy.accountAutoLogin] }.first ?? ""
            findings.append(Finding(
                control: "auto_login",
                status: "fail",
                severity: "high",
                title: "Automatic login enabled",
                detail: "Auto-login appears configured\(user.isEmpty ? "" : " for user \(user)"). kcpassword presence implies credential material at rest (bytes not exported).",
                remediation: "Disable automatic login via System Settings or sysadminctl -autologin off. Treat /etc/kcpassword presence as credential material - collect under custody, do not export password bytes.",
                evidence: user.isEmpty ? "auto_login_enabled" : "autoLoginUser=\(user)"
            ))
        }
        return findings
    }

    static func assessSoftwareUpdate(_ events: [EventEnvelope]) -> [Finding] {
        var findings: [Finding] = []

        let customCatalog = events.filter {
            $0.fields["su.catalog_non_apple"] == "true"
                || (($0.fields["su.catalog_url"] ?? "").isEmpty == false
                    && !($0.fields["su.catalog_url"] ?? "").contains("apple.com"))
        }
        if let hit = customCatalog.first {
            findings.append(Finding(
                control: "software_update_catalog",
                status: "fail",
                severity: "high",
                title: "Non-Apple software update catalog",
                detail: "Software Update CatalogURL points away from Apple defaults - supply-chain / misconfig risk.",
                remediation: "Reset software update catalog to Apple default (softwareupdate --clear-catalog / remove CatalogURL). Investigate who set the custom catalog (malware, rouge MDM, misconfig).",
                evidence: hit.fields["su.catalog_url"] ?? hit.rawRef ?? ""
            ))
        }

        let autoOff = events.filter {
            ($0.fields["protection.name"] ?? "").lowercased().contains("softwareupdateauto")
                && $0.fields["protection.enabled"] == "false"
        }
        if !autoOff.isEmpty {
            findings.append(Finding(
                control: "software_update_auto",
                status: "fail",
                severity: "medium",
                title: "Automatic software update check disabled",
                detail: "AutomaticCheckEnabled appears off - hosts may miss XProtect/security updates.",
                remediation: "Re-enable automatic security updates and XProtect/config data updates. If deferrals are intentional, document MDM deferral window and enforcement plan.",
                evidence: autoOff.first?.rawRef ?? "AutomaticCheckEnabled=false"
            ))
        }
        return findings
    }

    static func assessLockdownMode(_ events: [EventEnvelope]) -> [Finding] {
        let ldm = events.filter {
            ($0.fields["protection.name"] ?? "").lowercased().contains("lockdown")
                || $0.fields["lockdown.enabled"] != nil
        }
        guard let hit = ldm.first else { return [] }
        let enabled = hit.fields["lockdown.enabled"] ?? hit.fields["protection.enabled"] ?? "unknown"
        if enabled == "true" {
            return [
                Finding(
                    control: "lockdown_mode",
                    status: "pass",
                    severity: "info",
                    title: "Lockdown Mode enabled",
                    detail: "Lockdown Mode appears enabled for at least one user profile.",
                    remediation: "No action for high-risk personas. Expect app/web feature breakage.",
                    evidence: hit.rawRef ?? ""
                ),
            ]
        }
        if enabled == "false" {
            return [
                Finding(
                    control: "lockdown_mode",
                    status: "warn",
                    severity: "low",
                    title: "Lockdown Mode not enabled",
                    detail: "LDMGlobalEnabled indicates Lockdown Mode is off (persona-dependent; not a fleet-wide fail).",
                    remediation: "Consider Lockdown Mode (Privacy & Security) for high-risk users; expect app/web breakage. Not a fleet-wide mandate.",
                    evidence: hit.rawRef ?? "lockdown_mode=disabled"
                ),
            ]
        }
        return []
    }

    // MARK: - Wave-5 assessments

    private static func isRiskyPrivilegedHelper(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        let label = (fields["privhelper.label"] ?? fields["persistence.label"] ?? "").lowercased()
        let team = (fields["privhelper.team_id"] ?? fields["helper.team_id"] ?? "").lowercased()
        return containsAny((fields["persistence.risk_tags"] ?? "").lowercased(), terms: ["unknown_team", "orphan", "tmp_path"])
            || containsAny(label, terms: ["evil"])
            || team == "unknown"
            || (team.isEmpty && label.contains("evil"))
    }

    private static func isAccountPostureEvent(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return [event.eventType == "ir.posture.account", fields["account.kind"] != nil, fields["account.guest_enabled"] != nil, fields["account.auto_login_enabled"] != nil, fields["account.kcpassword_present"] == "true"].contains(true)
    }

    private static func isGuestAccountEnabled(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return [(fields["account.kind"] == "guest" && fields["account.enabled"] == "true"), fields["account.guest_enabled"] == "true", fields[FieldTaxonomy.accountGuestEnabled] == "true"].contains(true)
    }

    private static func isAutoLoginEnabled(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return [(fields["account.kind"] == "auto_login" && fields["account.enabled"] == "true"), fields["account.auto_login_enabled"] == "true", fields["account.kcpassword_present"] == "true", !(fields["account.auto_login_user"] ?? "").isEmpty].contains(true)
    }
}
