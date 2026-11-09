import Foundation
import RootstockBlueCore

/// SSH keys and config forensics - metadata only (never dumps private key material as secrets).
public struct SSHArtifactsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SSH",
        tier: .tier2,
        description: "SSH authorized_keys, known_hosts, and sshd_config directives"
    )

    /// Interesting sshd_config directives for IR (auth posture).
    private static let interestingDirectives: Set<String> = [
        "PermitRootLogin",
        "PasswordAuthentication",
        "PubkeyAuthentication",
        "PermitEmptyPasswords",
        "ChallengeResponseAuthentication",
        "UsePAM",
        "X11Forwarding",
        "AllowUsers",
        "DenyUsers",
        "AllowGroups",
        "DenyGroups",
        "AuthorizedKeysFile",
        "Port",
        "ListenAddress",
        "Protocol",
        "MaxAuthTries",
    ]

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        return parseArtifacts(root, paths: [], matching: Self.isAuthorizedKey, seen: &seen, parse: parseAuthorizedKeys)
            + parseArtifacts(root, paths: [], matching: Self.isKnownHost, seen: &seen, parse: parseKnownHosts)
            + parseArtifacts(root, paths: Self.sshdConfigPaths, matching: Self.isSSHDConfig, seen: &seen, parse: parseSSHDConfig)
    }

    private static let sshdConfigPaths = ["etc/ssh/sshd_config", "private/etc/ssh/sshd_config", "etc/sshd_config"]

    private func parseArtifacts(
        _ root: ArtifactRoot,
        paths: [String],
        matching: (URL) -> Bool,
        seen: inout PathDeduper,
        parse: (URL) -> [EventEnvelope]
    ) -> [EventEnvelope] {
        let configured = paths.compactMap { root.firstExisting([$0]) }
        let discovered = root.enumerate(matching: matching)
        return (configured + discovered).flatMap { seen.insert($0) ? parse($0) : [] }
    }

    private static func isAuthorizedKey(_ url: URL) -> Bool {
        ["authorized_keys", "authorized_keys2"].contains(url.lastPathComponent) && url.path.contains(".ssh")
    }

    private static func isKnownHost(_ url: URL) -> Bool {
        url.lastPathComponent == "known_hosts" && url.path.contains(".ssh")
    }

    /// `sshd_config` plus its `sshd_config.d` drop-ins (not `ssh_config.d`, which is client config).
    private static func isSSHDConfig(_ url: URL) -> Bool {
        !url.hasDirectoryPath
            && (url.lastPathComponent == "sshd_config" || url.deletingLastPathComponent().lastPathComponent == "sshd_config.d")
    }

    // MARK: - authorized_keys

    private func parseAuthorizedKeys(at url: URL) -> [EventEnvelope] {
        guard let text = ArtifactIO.text(contentsOf: url) else { return [] }
        let user = inferUser(from: url)
        return text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).enumerated().compactMap {
            authorizedKeyEvent(rawLine: String($0.element), lineNumber: $0.offset + 1, url: url, user: user)
        }
    }

    private func authorizedKeyEvent(rawLine: String, lineNumber: Int, url: URL, user: String?) -> EventEnvelope? {
        let line = rawLine.trimmingCharacters(in: .whitespaces)
        let parsed = parseAuthorizedKeyLine(line)
        guard !line.isEmpty, !line.hasPrefix("#"), let keyType = parsed.keyType else { return nil }
        let path = ArtifactRoot.pathKey(url)
        return EventEnvelope(identity: EventEnvelope.Identity(kind: "auth.ssh_authorized_key", label: "SSH"), capture: EventEnvelope.Capture(source: .parser, eventTime: fileMTime(url), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: authorizedKeyEntities(user: user, keyType: keyType, comment: parsed.comment, path: path), properties: authorizedKeyFields(parsed: parsed, user: user, lineNumber: lineNumber, path: path), provenance: path, confidence: 0.96))
    }

    private func authorizedKeyFields(parsed: AuthorizedKey, user: String?, lineNumber: Int, path: String) -> [String: String] {
        var fields = ["ssh.key_type": parsed.keyType ?? "", "ssh.key_comment": parsed.comment, "ssh.options": parsed.options, "ssh.user": user ?? "", "ssh.line": String(lineNumber), FieldTaxonomy.filePath: path, FieldTaxonomy.eventType: "auth.ssh_authorized_key"]
        if let user { fields[FieldTaxonomy.userName] = user }
        return fields
    }

    private func authorizedKeyEntities(user: String?, keyType: String, comment: String, path: String) -> [EntityID] {
        var entities: [EntityID] = [EntityID(kind: .auth, value: "ssh_authorized_key|\(user ?? "unknown")|\(keyType)|\(comment)"), .file(path: path)]
        if let user { entities.append(.user(name: user)) }
        return entities
    }

    /// Parse OpenSSH authorized_keys line: [options] key-type base64-key [comment]
    private func parseAuthorizedKeyLine(_ line: String) -> AuthorizedKey {
        let tokens = line.split(separator: " ", omittingEmptySubsequences: true).map { String($0) }
        guard !tokens.isEmpty else { return .empty }
        if let index = tokens.firstIndex(where: { Self.knownKeyTypes.contains($0) }) {
            return Self.authorizedKey(tokens, keyTypeIndex: index)
        }
        return Self.heuristicAuthorizedKey(tokens)
    }

    private static let knownKeyTypes: Set<String> = [
        "ssh-ed25519", "ssh-rsa", "ssh-dss", "ssh-ecdsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com",
    ]

    private static func authorizedKey(_ tokens: [String], keyTypeIndex: Int) -> AuthorizedKey {
        let commentStart = keyTypeIndex + 2
        let comment = commentStart < tokens.count ? tokens[commentStart...].joined(separator: " ") : ""
        return AuthorizedKey(options: tokens[..<keyTypeIndex].joined(separator: " "), keyType: tokens[keyTypeIndex], comment: comment)
    }

    private static func heuristicAuthorizedKey(_ tokens: [String]) -> AuthorizedKey {
        guard tokens.count >= 2, ["ssh-", "ecdsa-", "sk-"].contains(where: tokens[0].hasPrefix) else { return .empty }
        let comment = tokens.count > 2 ? tokens[2...].joined(separator: " ") : ""
        return AuthorizedKey(options: "", keyType: tokens[0], comment: comment)
    }

    private struct AuthorizedKey {
        let options: String
        let keyType: String?
        let comment: String

        static let empty = AuthorizedKey(options: "", keyType: nil, comment: "")
    }

    // MARK: - known_hosts

    private func parseKnownHosts(at url: URL) -> [EventEnvelope] {
        guard let text = ArtifactIO.text(contentsOf: url) else { return [] }
        let user = inferUser(from: url)
        var events: [EventEnvelope] = []
        var lineNo = 0

        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            lineNo += 1
            var line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }

            // Strip optional @cert-authority / @revoked markers.
            var marker = ""
            if line.hasPrefix("@") {
                let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
                if parts.count == 2 {
                    marker = String(parts[0])
                    line = String(parts[1])
                }
            }

            guard let event = knownHostEvent(from: line, marker: marker, url: url, user: user, lineNo: lineNo) else { continue }
            events.append(event)
        }
        return events
    }

    private func knownHostEvent(from line: String, marker: String, url: URL, user: String?, lineNo: Int) -> EventEnvelope? {
        let tokens = line.split(separator: " ", omittingEmptySubsequences: true).map { String($0) }
        guard tokens.count >= 2 else { return nil }
        let path = ArtifactRoot.pathKey(url)
        let hostPattern = tokens[0]
        let keyType = tokens[1]
        var fields: [String: String] = ["ssh.host_pattern": hostPattern, "ssh.key_type": keyType, "ssh.line": String(lineNo), FieldTaxonomy.filePath: path, FieldTaxonomy.eventType: "auth.ssh_known_host"]
        if !marker.isEmpty { fields["ssh.marker"] = marker }
        if let user {
            fields[FieldTaxonomy.userName] = user
            fields["ssh.user"] = user
        }
        var entities: [EntityID] = [EntityID(kind: .auth, value: "ssh_known_host|\(hostPattern)|\(keyType)"), .file(path: path)]
        if let user { entities.append(.user(name: user)) }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "auth.ssh_known_host",
                label: "SSH"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: fileMTime(url),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: entities,
                properties: fields,
                provenance: path,
                confidence: 0.94
            )
        )
    }

    // MARK: - sshd_config

    /// sshd_config(5) separates keyword and argument with whitespace and/or one `=`.
    static func splitDirective(_ line: String) -> (directive: String, value: String)? {
        // sshd splits on space and tab only; other Unicode spaces are part of the token.
        let blank: (Character) -> Bool = { $0 == " " || $0 == "\t" }
        let keyEnd = line.firstIndex { blank($0) || $0 == "=" } ?? line.endIndex
        var rest = line[keyEnd...].drop(while: blank)
        if rest.hasPrefix("=") { rest = rest.dropFirst() }
        let value = rest.split(whereSeparator: blank).joined(separator: " ")
        return value.isEmpty ? nil : (String(line[..<keyEnd]), value)
    }

    private func parseSSHDConfig(at url: URL) -> [EventEnvelope] {
        guard let text = ArtifactIO.text(contentsOf: url) else { return [] }
        var events: [EventEnvelope] = []
        var lineNo = 0

        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            lineNo += 1
            let trimmed = String(rawLine).trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            guard let (directive, value) = Self.splitDirective(trimmed) else { continue }
            // Match case-insensitively against interesting set.
            let matched = Self.interestingDirectives.first { $0.caseInsensitiveCompare(directive) == .orderedSame }
            guard let canonical = matched else { continue }

            events.append(
                EventEnvelope(
                    identity: EventEnvelope.Identity(
                        kind: "auth.sshd_config",
                        label: "SSH"
                    ),
                    capture: EventEnvelope.Capture(
                        source: .parser,
                        eventTime: fileMTime(url),
                        collectedAt: Date()
                    ),
                    payload: EventEnvelope.Payload(
                        entityRefs: [
                        EntityID(kind: .auth, value: "sshd_config|\(canonical)"),
                        .file(path: ArtifactRoot.pathKey(url)),
                        EntityID(kind: .host, value: "sshd"),
                    ],
                        properties: [
                        "ssh.directive": canonical,
                        "ssh.value": value,
                        "ssh.line": String(lineNo),
                        FieldTaxonomy.filePath: ArtifactRoot.pathKey(url),
                        FieldTaxonomy.eventType: "auth.sshd_config",
                    ],
                        provenance: ArtifactRoot.pathKey(url),
                        confidence: 0.97
                    )
                )
            )
        }
        return events
    }

    // MARK: - helpers

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
