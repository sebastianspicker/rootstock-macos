import Foundation
import RootstockCore

/// Sharing / remote-access posture via LaunchDaemon and prefs path heuristics.
///
/// No shell storm, no listening-port scan (often needs root). System LaunchDaemon
/// plists often exist even when the service is disabled - path presence is inventory,
/// not proof of enablement. Details live in `NetworkState.notes` / collectorNotes.
public struct NetworkCollector: Collector {
    public static let id = "collect.network"
    public static let cost: CollectorCost = .medium

    private static let sshPlists = [
        "/System/Library/LaunchDaemons/ssh.plist",
        "/System/Library/LaunchDaemons/com.openssh.sshd.plist",
    ]
    private static let screenSharingPlists = [
        "/System/Library/LaunchDaemons/com.apple.screensharing.plist",
        "/System/Library/LaunchAgents/com.apple.screensharing.agent.plist",
        "/System/Library/LaunchAgents/com.apple.screensharing.MessagesAgent.plist",
    ]
    private static let remoteManagementPreferences = [
        "/Library/Preferences/com.apple.RemoteManagement.plist",
        "/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd",
    ]
    private static let fileSharingPlists = [
        "/System/Library/LaunchDaemons/com.apple.smbd.plist",
        "/System/Library/LaunchDaemons/com.apple.AppleFileServer.plist",
        "/System/Library/LaunchDaemons/com.apple.smb.preferences.plist",
    ]

    private struct ProbeSummary {
        let remoteLoginPlistPresent: Bool
        let screenSharingPlistPresent: Bool
        let fileSharingPlistPresent: Bool
        let remoteManagementPrefsPresent: Bool
        let sshdConfigPresent: Bool
        var notes: [String]
    }

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var summary = Self.probe(fileManager: fm)

        // Likely-enabled (conservative): system plists alone are insufficient.
        // RemoteManagement prefs are a stronger ARD/screen-sharing configuration signal.
        // SSH/SMB enablement requires launchctl/systemsetup - leave nil without shell.
        let remoteLoginSSH: Bool? = nil
        let screenSharingARD: Bool? = summary.remoteManagementPrefsPresent ? true : nil
        let fileSharingSMB: Bool? = nil
        summary.notes.append(
            "Likely-enabled: ssh=\(remoteLoginSSH.map(String.init(describing:)) ?? "nil") "
                + "screen=\(screenSharingARD.map(String.init(describing:)) ?? "nil") "
                + "file=\(fileSharingSMB.map(String.init(describing:)) ?? "nil")"
        )

        var state = CollectedState()
        state.network = NetworkState(reachability: .init(remoteLoginSSH: remoteLoginSSH, screenSharingARD: screenSharingARD, fileSharingSMB: fileSharingSMB), artifacts: .init(remoteLoginPlistPresent: summary.remoteLoginPlistPresent, screenSharingPlistPresent: summary.screenSharingPlistPresent, fileSharingPlistPresent: summary.fileSharingPlistPresent, remoteManagementPrefsPresent: summary.remoteManagementPrefsPresent, sshdConfigPresent: summary.sshdConfigPresent), notes: summary.notes)
        state.collectorNotes[Self.id] =
            "sharing path heuristics (sshPlist=\(summary.remoteLoginPlistPresent), screenPlist=\(summary.screenSharingPlistPresent), filePlist=\(summary.fileSharingPlistPresent), ardPrefs=\(summary.remoteManagementPrefsPresent))"
        return state
    }

    private static func probe(fileManager: FileManager) -> ProbeSummary {
        var notes = [
            "Path-heuristic network/sharing posture only",
            "LaunchDaemon presence ≠ service enabled; listening ports not scanned (avoid root/shell storm)",
        ]
        let ssh = record(paths: sshPlists, label: "Remote Login", fileManager: fileManager, notes: &notes)
        let sshConfig = fileManager.fileExists(atPath: "/etc/ssh/sshd_config")
            || fileManager.fileExists(atPath: "/private/etc/ssh/sshd_config")
        notes.append("Remote Login: sshd_config present=\(sshConfig)")
        let screen = record(paths: screenSharingPlists, label: "Screen Sharing", fileManager: fileManager, notes: &notes)
        let management = record(paths: remoteManagementPreferences, label: "Remote Management", fileManager: fileManager, notes: &notes)
        let fileSharing = record(paths: fileSharingPlists, label: "File Sharing", fileManager: fileManager, notes: &notes)
        appendExtraSurfaces(fileManager: fileManager, notes: &notes)
        appendLaunchdOverrides(fileManager: fileManager, notes: &notes)
        notes.append("Summary: sshPlist=\(ssh) screenSharingPlist=\(screen) fileSharingPlist=\(fileSharing) remoteMgmtPrefs=\(management)")
        if management {
            notes.append("RemoteManagement prefs present - ARD/screen sharing was likely configured at some point (not definitive live state)")
        }
        return ProbeSummary(remoteLoginPlistPresent: ssh, screenSharingPlistPresent: screen, fileSharingPlistPresent: fileSharing, remoteManagementPrefsPresent: management, sshdConfigPresent: sshConfig, notes: notes)
    }

    private static func record(paths: [String], label: String, fileManager: FileManager, notes: inout [String]) -> Bool {
        for path in paths {
            notes.append("\(label): \(path) exists=\(fileManager.fileExists(atPath: path))")
        }
        return paths.contains { fileManager.fileExists(atPath: $0) }
    }

    private static func appendExtraSurfaces(fileManager: FileManager, notes: inout [String]) {
        let surfaces = [
            ("Printer Sharing", "/System/Library/LaunchDaemons/org.cups.cupsd.plist"),
            ("Remote Apple Events", "/System/Library/LaunchDaemons/com.apple.AEServer.plist"),
            ("AirPlay Receiver agent", "/System/Library/LaunchAgents/com.apple.AirPlayUIAgent.plist"),
        ]
        for (label, path) in surfaces {
            notes.append("\(label): \(path) exists=\(fileManager.fileExists(atPath: path))")
        }
    }

    private static func appendLaunchdOverrides(fileManager: FileManager, notes: inout [String]) {
        for path in [
            "/var/db/com.apple.xpc.launchd/disabled.plist",
            "/var/db/launchd.db/com.apple.launchd/overrides.plist",
        ] {
            let exists = fileManager.fileExists(atPath: path)
            let readable = fileManager.isReadableFile(atPath: path)
            notes.append("launchd overrides: \(path) exists=\(exists) readable=\(readable)")
        }
    }
}
