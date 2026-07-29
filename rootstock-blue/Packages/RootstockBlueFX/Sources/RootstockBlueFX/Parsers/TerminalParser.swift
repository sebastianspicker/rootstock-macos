/// Offline forensic parser: TerminalParser - fixture-backed IR events (no secret export).
import Foundation
import RootstockBlueCore

public struct TerminalParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "TERMSESSIONS",
        tier: .tier1,
        description: "Shell history files (.zsh_history, .bash_history)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        let histories = root.enumerate { url in
            let name = url.lastPathComponent
            return name == ".zsh_history" || name == ".bash_history" || name == "fish_history"
        }
        var events: [EventEnvelope] = []
        for hist in histories {
            events.append(contentsOf: parseHistory(at: hist))
        }
        return events
    }

    private func parseHistory(at url: URL) -> [EventEnvelope] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let user = inferUser(from: url)
        var events: [EventEnvelope] = []
        var index = 0
        for line in text.split(whereSeparator: \.isNewline) {
            let cmd = String(line).trimmingCharacters(in: .whitespaces)
            if cmd.isEmpty { continue }
            index += 1
            // Skip zsh extended history metadata lines starting with `: `
            let command: String
            if cmd.hasPrefix(": ") {
                // : 1700000000:0;actual command
                if let semi = cmd.firstIndex(of: ";") {
                    command = String(cmd[cmd.index(after: semi)...])
                } else {
                    continue
                }
            } else {
                command = cmd
            }
            events.append(
                EventEnvelope(
                    identity: EventEnvelope.Identity(
                        kind: "shell.history",
                        label: "TERMSESSIONS"
                    ),
                    capture: EventEnvelope.Capture(
                        source: .parser,
                        eventTime: Date(timeIntervalSince1970: 0),
                        collectedAt: Date()
                    ),
                    payload: EventEnvelope.Payload(
                        entityRefs: user.map { [.user(name: $0)] } ?? [],
                        properties: [
                        "shell.command": command,
                        "shell.history_path": url.path,
                        "shell.line": String(index),
                        FieldTaxonomy.userName: user ?? "",
                        FieldTaxonomy.eventType: "shell.history",
                    ],
                        provenance: url.path,
                        confidence: 0.85
                    )
                )
            )
        }
        return events
    }

}
