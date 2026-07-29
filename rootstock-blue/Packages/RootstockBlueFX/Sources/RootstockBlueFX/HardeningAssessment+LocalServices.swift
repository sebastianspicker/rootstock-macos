import Foundation
import RootstockBlueCore
import RootstockBlueCase
extension HardeningAssessment {

    static func assessPhotosLibraryPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "PHOTOSLIBRARY" || $0.eventType == "photos.library"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["photoslib.risk_tags"] ?? "").lowercased()
            return tags.contains("photos_surface") || !($0.fields["photoslib.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["photoslib.path"] ?? ""
            let name = $0.fields["photoslib.name"] ?? ""
            let tags = $0.fields["photoslib.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "photos_library_path", status: "fail", severity: "medium",
            title: "Photos.app library collection path plane surface present",
            detail: "\(risky.count) Photos library path plane marker(s) - IR surface. Path/meta only; never reads photo contents or exports Photo Library media.",
            remediation: "Inventory and baseline Photos library path plane artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessVpnConfigDualuse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "VPNCONFIGDUAL" || $0.eventType == "vpn.config"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["vpncfg.risk_tags"] ?? "").lowercased()
            return tags.contains("vpn_surface") || !($0.fields["vpncfg.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["vpncfg.path"] ?? ""
            let name = $0.fields["vpncfg.name"] ?? ""
            let tags = $0.fields["vpncfg.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "vpn_config_dualuse", status: "fail", severity: "medium",
            title: "VPN configuration dual-use residual surface surface present",
            detail: "\(risky.count) VPN config dual-use marker(s) - IR surface. Path/meta only; never installs VPN profiles or rewrites network extension VPN configs.",
            remediation: "Inventory and baseline VPN config dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessSandboxContainerDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SANDBOXCONTAINER" || $0.eventType == "sandbox.container"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["sbxctr.risk_tags"] ?? "").lowercased()
            return tags.contains("sandbox_surface") || !($0.fields["sbxctr.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["sbxctr.path"] ?? ""
            let name = $0.fields["sbxctr.name"] ?? ""
            let tags = $0.fields["sbxctr.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "sandbox_container_depth", status: "fail", severity: "medium",
            title: "App sandbox container residual depth surface present",
            detail: "\(risky.count) Sandbox container depth marker(s) - IR surface. Path/meta only; never breaks app sandbox or forges container entitlements.",
            remediation: "Inventory and baseline Sandbox container depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessXpcMachServiceDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "XPCMACHSERVICE" || $0.eventType == "xpc.mach_service"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["xpcmach.risk_tags"] ?? "").lowercased()
            return tags.contains("xpc_mach_surface") || !($0.fields["xpcmach.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["xpcmach.path"] ?? ""
            let name = $0.fields["xpcmach.name"] ?? ""
            let tags = $0.fields["xpcmach.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "xpc_mach_service_depth", status: "fail", severity: "medium",
            title: "XPC Mach service residual depth surface present",
            detail: "\(risky.count) XPC Mach service depth marker(s) - IR surface. Path/meta only; never registers XPC services or injects into Mach ports.",
            remediation: "Inventory and baseline XPC Mach service depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessTmLocalSnapshotDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "TMLOCALSNAPSHOT" || $0.eventType == "tm.local_snapshot"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["tmsnap.risk_tags"] ?? "").lowercased()
            return tags.contains("tm_snapshot_surface") || !($0.fields["tmsnap.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["tmsnap.path"] ?? ""
            let name = $0.fields["tmsnap.name"] ?? ""
            let tags = $0.fields["tmsnap.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "tm_local_snapshot_depth", status: "fail", severity: "medium",
            title: "Time Machine local snapshot residual depth surface present",
            detail: "\(risky.count) TM local snapshot depth marker(s) - IR surface. Path/meta only; never mounts snapshots for data theft or deletes backup catalogs.",
            remediation: "Inventory and baseline TM local snapshot depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessEmondLegacyDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "EMONDLEGACY" || $0.eventType == "emond.legacy"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["emondleg.risk_tags"] ?? "").lowercased()
            return tags.contains("emond_surface") || !($0.fields["emondleg.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["emondleg.path"] ?? ""
            let name = $0.fields["emondleg.name"] ?? ""
            let tags = $0.fields["emondleg.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "emond_legacy_depth", status: "fail", severity: "medium",
            title: "Emond legacy rules residual depth surface present",
            detail: "\(risky.count) Emond legacy depth marker(s) - IR surface. Path/meta only; never installs emond rules or enables the legacy event monitor daemon.",
            remediation: "Inventory and baseline Emond legacy depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessScreenSharingArdDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SCREENSHARINGARD" || $0.eventType == "ard.screen_sharing"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["ardss.risk_tags"] ?? "").lowercased()
            return tags.contains("ard_surface") || !($0.fields["ardss.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["ardss.path"] ?? ""
            let name = $0.fields["ardss.name"] ?? ""
            let tags = $0.fields["ardss.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "screen_sharing_ard_depth", status: "fail", severity: "medium",
            title: "Screen Sharing / ARD residual depth surface present",
            detail: "\(risky.count) Screen Sharing ARD depth marker(s) - IR surface. Path/meta only; never enables Screen Sharing or ARD, never connects to remote desktops.",
            remediation: "Inventory and baseline Screen Sharing ARD depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessKeychainAclPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "KEYCHAINACLPATH" || $0.eventType == "keychain.acl_path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["kcacl.risk_tags"] ?? "").lowercased()
            return tags.contains("keychain_acl_surface") || !($0.fields["kcacl.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["kcacl.path"] ?? ""
            let name = $0.fields["kcacl.name"] ?? ""
            let tags = $0.fields["kcacl.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "keychain_acl_path", status: "fail", severity: "medium",
            title: "Keychain ACL path residual surface surface present",
            detail: "\(risky.count) Keychain ACL path plane marker(s) - IR surface. Path/meta only; never dumps keychain items, passwords, or private keys.",
            remediation: "Inventory and baseline Keychain ACL path plane artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessPythonRuntimeDualuse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "PYTHONRUNTIME" || $0.eventType == "python.runtime"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["pyrun.risk_tags"] ?? "").lowercased()
            return tags.contains("python_surface") || !($0.fields["pyrun.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["pyrun.path"] ?? ""
            let name = $0.fields["pyrun.name"] ?? ""
            let tags = $0.fields["pyrun.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "python_runtime_dualuse", status: "fail", severity: "medium",
            title: "Python runtime dual-use residual surface surface present",
            detail: "\(risky.count) Python runtime dual-use marker(s) - IR surface. Path/meta only; never executes third-party Python payloads or drops malicious site-packages.",
            remediation: "Inventory and baseline Python runtime dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    static func assessShellPluginManager(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SHELLPLUGINMGR" || $0.eventType == "shell.plugin_manager"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["shplug.risk_tags"] ?? "").lowercased()
            return tags.contains("shell_plugin_surface") || !($0.fields["shplug.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["shplug.path"] ?? ""
            let name = $0.fields["shplug.name"] ?? ""
            let tags = $0.fields["shplug.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "shell_plugin_manager", status: "fail", severity: "medium",
            title: "Shell plugin manager dual-use residual surface present",
            detail: "\(risky.count) Shell plugin manager dual-use marker(s) - IR surface. Path/meta only; never installs oh-my-zsh plugins or rewrites shell init for persistence.",
            remediation: "Inventory and baseline Shell plugin manager dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }
    // MARK: - Wave-16 multi-plane red↔blue pair assessments

}
