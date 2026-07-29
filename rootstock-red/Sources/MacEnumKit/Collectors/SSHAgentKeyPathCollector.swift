import Foundation
import RootstockCore

/// SSH-agent / key path lateral posture depth (Wave-8).
///
/// Research basis: SSH lateral checklists; agent socket and authorized_keys path awareness.
/// Safety and behavior: typed `SSHAgentKeyPathState`; paths only - never reads key material.
public struct SSHAgentKeyPathCollector: Collector {
    public static let id = "collect.ssh_agent_key_path"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let home = NSHomeDirectory()
        var notes: [String] = [
            "SSH agent/key path surface: path presence only - never reads private keys or agent material",
        ]

        let agentSockets = Self.agentSocketPaths(fileManager: fm, home: home, notes: &notes)
        let keyPaths = Self.keyPathHits(fileManager: fm, home: home, notes: &notes)
        let sshdSupport = Self.sshdSupportPaths(fileManager: fm, notes: &notes)

        let surface = !agentSockets.isEmpty || !keyPaths.isEmpty || !sshdSupport.isEmpty

        var state = CollectedState()
        state.sshAgentKeyPath = SSHAgentKeyPathState(
            agentSocketPaths: agentSockets,
            keyPathHits: keyPaths,
            sshdSupportPaths: sshdSupport,
            lateralPathSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "agent=\(agentSockets.count) keys=\(keyPaths.count) "
            + "sshd=\(sshdSupport.count) surface=\(surface)"
        return state
    }

    private static func agentSocketPaths(
        fileManager: FileManager,
        home: String,
        notes: inout [String]
    ) -> [String] {
        var paths: [String] = []
        if let socket = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"], !socket.isEmpty {
            paths.append(socket)
            notes.append("SSH_AUTH_SOCK path observed (not connected): \(socket)")
            if fileManager.fileExists(atPath: socket) {
                notes.append("agent_socket_exists: \(socket)")
            }
        }
        let candidates = [
            home + "/.ssh/agent.sock",
            "/private/tmp/com.apple.launchd." ,
            "/var/run/ssh-agent.sock",
            home + "/Library/Containers/com.openssh.ssh-agent",
            "/System/Library/LaunchAgents/com.openssh.ssh-agent.plist",
            "/System/Library/LaunchDaemons/ssh.plist",
            "/usr/bin/ssh-agent",
            "/usr/bin/ssh-add",
        ]
        for path in candidates {
            guard !path.hasSuffix("com.apple.launchd.") else {
                // Prefix only - do not enumerate /private/tmp broadly; note class
                notes.append("agent_class_hint: launchd tmp socket class (not enumerated)")
                continue
            }
            if fileManager.fileExists(atPath: path) {
                paths.append(path)
                notes.append("agent_or_tool: \(path)")
            }
        }
        return Array(Set(paths)).sorted()
    }

    private static func keyPathHits(
        fileManager: FileManager,
        home: String,
        notes: inout [String]
    ) -> [String] {
        let candidates = [
            home + "/.ssh/authorized_keys",
            home + "/.ssh/authorized_keys2",
            home + "/.ssh/known_hosts",
            home + "/.ssh/config",
            home + "/.ssh/id_rsa",
            home + "/.ssh/id_ed25519",
            home + "/.ssh/id_ecdsa",
            home + "/.ssh/id_dsa",
            "/etc/ssh/sshd_config",
            "/etc/ssh/ssh_config",
            "/private/etc/ssh/sshd_config",
        ]
        var paths = candidates.filter { fileManager.fileExists(atPath: $0) }
        for path in paths {
            // Record path only - never open private key files for content
            let isPrivate = path.contains("id_rsa") || path.contains("id_ed25519")
                || path.contains("id_ecdsa") || path.contains("id_dsa")
            notes.append(isPrivate ? "private_key_path_present: \(path)" : "ssh_path: \(path)")
        }

        // List additional public keys (*.pub) under ~/.ssh without reading material
        let directory = home + "/.ssh"
        if fileManager.fileExists(atPath: directory),
           let entries = try? fileManager.contentsOfDirectory(atPath: directory)
        {
            for entry in entries.prefix(40) where entry.hasSuffix(".pub") {
                    let full = (directory as NSString).appendingPathComponent(entry)
                    paths.append(full)
                    notes.append("public_key_path: \(full)")
            }
        }
        return Array(Set(paths)).sorted()
    }

    private static func sshdSupportPaths(fileManager: FileManager, notes: inout [String]) -> [String] {
        let candidates = [
            "/usr/sbin/sshd",
            "/usr/bin/ssh",
            "/usr/libexec/sshd-keygen-wrapper",
            "/System/Library/LaunchDaemons/ssh.plist",
            "/etc/ssh",
            "/private/etc/ssh",
        ]
        let paths = candidates.filter { fileManager.fileExists(atPath: $0) }
        for path in paths {
            notes.append("sshd_support: \(path)")
        }
        return Array(Set(paths)).sorted()
    }
}
