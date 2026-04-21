import Foundation
import Models

/// Scans the filesystem for Kerberos artifacts (ccache, keytab, krb5.conf).
///
/// **Security note:** Only file metadata (path, owner, permissions, modification time)
/// is collected — file contents are never read.  The principal hint is inferred from
/// the ccache filename pattern (`krb5cc_<uid>` → getpwuid), not from the credential
/// cache itself.
///
/// No elevation required: `FileManager.attributesOfItem` works on any readable path.
public struct KerberosArtifactDataSource: DataSource {
    public let name = "Kerberos Artifacts"
    public let requiresElevation = false

    /// Well-known paths to scan for Kerberos artifacts.
    static let ccachePaths = ["/tmp", "/var/db/krb5cc"]
    static let keytabPaths = ["/etc/krb5.keytab"]
    static let configPaths = ["/etc/krb5.conf", "/Library/Preferences/edu.mit.Kerberos"]

    public init() {}

    public func collect() async -> DataSourceResult {
        var artifacts: [KerberosArtifact] = []
        var errors: [CollectionError] = []

        // Scan ccache directories
        for dir in Self.ccachePaths {
            artifacts.append(contentsOf: scanCcacheDirectory(dir, errors: &errors))
        }

        // Check well-known keytab paths
        for path in Self.keytabPaths {
            if let artifact = probeFile(path: path, type: .keytab) {
                artifacts.append(artifact)
            }
        }

        // Check config paths
        for path in Self.configPaths {
            if let artifact = probeFile(path: path, type: .config) {
                artifacts.append(artifact)
            }
        }

        return DataSourceResult(
            nodes: artifacts,
            errors: errors
        )
    }

    // MARK: - Internal (visible for testing)

    /// Scan a directory for files matching `krb5cc_*`.
    func scanCcacheDirectory(_ directory: String, errors: inout [CollectionError]) -> [KerberosArtifact] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: directory) else { return [] }

        var results: [KerberosArtifact] = []

        guard let contents = try? fm.contentsOfDirectory(atPath: directory) else {
            return []
        }

        for entry in contents where entry.hasPrefix("krb5cc_") {
            let fullPath = (directory as NSString).appendingPathComponent(entry)
            if var artifact = probeFile(path: fullPath, type: .ccache) {
                // Infer principal from filename pattern krb5cc_<uid>
                let principal = inferPrincipalFromFilename(entry)
                artifact = KerberosArtifact(
                    path: artifact.path,
                    artifactType: artifact.artifactType,
                    owner: artifact.owner,
                    group: artifact.group,
                    mode: artifact.mode,
                    modificationTime: artifact.modificationTime,
                    principalHint: principal ?? artifact.principalHint,
                    isReadable: artifact.isReadable,
                    isWorldReadable: artifact.isWorldReadable,
                    isGroupReadable: artifact.isGroupReadable
                )
                results.append(artifact)
            }
        }
        return results
    }

    /// Probe a single file path for metadata without reading contents.
    /// For `config` type, also parses the krb5.conf content (safe — config, not credential).
    func probeFile(path: String, type: KerberosArtifactType) -> KerberosArtifact? {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return nil }

        guard let attrs = try? fm.attributesOfItem(atPath: path) else { return nil }

        let owner = attrs[.ownerAccountName] as? String
        let group = attrs[.groupOwnerAccountName] as? String
        let posixPerms = attrs[.posixPermissions] as? Int
        let mode = posixPerms.map { String(format: "%o", $0) }
        let modDate = attrs[.modificationDate] as? Date
        let modTime = modDate.map { ISO8601DateFormatter().string(from: $0) }
        let isReadable = fm.isReadableFile(atPath: path)
        let isWorldReadable = Self.isWorldReadable(mode: posixPerms)
        let isGroupReadable = Self.isGroupReadable(mode: posixPerms)

        // Parse krb5.conf content for config-type artifacts
        var defaultRealm: String? = nil
        var permittedEncTypes: [String]? = nil
        var realmNames: [String]? = nil
        var isForwardable: Bool? = nil

        if type == .config && isReadable {
            let parsed = parseKrb5Conf(path: path)
            defaultRealm = parsed.defaultRealm
            permittedEncTypes = parsed.permittedEncTypes
            realmNames = parsed.realmNames
            isForwardable = parsed.isForwardable
        }

        return KerberosArtifact(
            path: path,
            artifactType: type,
            owner: owner,
            group: group,
            mode: mode,
            modificationTime: modTime,
            principalHint: nil,
            isReadable: isReadable,
            isWorldReadable: isWorldReadable,
            isGroupReadable: isGroupReadable,
            defaultRealm: defaultRealm,
            permittedEncTypes: permittedEncTypes,
            realmNames: realmNames,
            isForwardable: isForwardable
        )
    }

    /// Infer a username from a ccache filename like `krb5cc_501`.
    /// Returns nil if the uid cannot be resolved.
    func inferPrincipalFromFilename(_ filename: String) -> String? {
        let prefix = "krb5cc_"
        guard filename.hasPrefix(prefix) else { return nil }

        let uidStr = String(filename.dropFirst(prefix.count))
        guard let uid = uid_t(uidStr) else { return nil }

        guard let pw = getpwuid(uid) else { return nil }
        return String(cString: pw.pointee.pw_name)
    }

    /// Check if POSIX permissions include world-read (others read bit).
    static func isWorldReadable(mode: Int?) -> Bool {
        guard let mode = mode else { return false }
        return (mode & 0o004) != 0
    }

    /// Check if POSIX permissions include group-read bit.
    static func isGroupReadable(mode: Int?) -> Bool {
        guard let mode = mode else { return false }
        return (mode & 0o040) != 0
    }

    // MARK: - krb5.conf parsing

    /// Parsed result from a krb5.conf file.
    struct Krb5Config {
        var defaultRealm: String?
        var permittedEncTypes: [String]?
        var realmNames: [String]?
        var isForwardable: Bool?
    }

    /// Parse a krb5.conf file to extract security-relevant configuration.
    ///
    /// krb5.conf is a standard MIT Kerberos INI-like format with sections
    /// (`[libdefaults]`, `[realms]`, `[domain_realm]`).  This parser extracts:
    /// - `default_realm` — the realm used by default
    /// - `permitted_enctypes` / `default_tkt_enctypes` — encryption preferences
    /// - realm names from `[realms]` section headers
    /// - `forwardable` flag (security-relevant default)
    ///
    /// **Security note:** krb5.conf is a config file, not a credential store.
    func parseKrb5Conf(path: String) -> Krb5Config {
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            return Krb5Config()
        }
        return parseKrb5ConfContents(contents)
    }

    /// Parse krb5.conf contents (extracted for testability).
    func parseKrb5ConfContents(_ contents: String) -> Krb5Config {
        var config = Krb5Config()
        var currentSection = ""
        var realmNames: [String] = []

        for line in contents.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Skip comments and empty lines
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix(";") {
                continue
            }

            // Section header: [libdefaults], [realms], etc.
            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                currentSection = String(trimmed.dropFirst().dropLast())
                    .trimmingCharacters(in: .whitespaces)
                    .lowercased()
                continue
            }

            switch currentSection {
            case "libdefaults":
                if let value = extractValue(trimmed, key: "default_realm") {
                    config.defaultRealm = value
                } else if config.permittedEncTypes == nil,
                          let value = extractValue(trimmed, key: "permitted_enctypes")
                            ?? extractValue(trimmed, key: "default_tkt_enctypes")
                            ?? extractValue(trimmed, key: "default_tgs_enctypes") {
                    config.permittedEncTypes = value
                        .split(whereSeparator: { $0 == " " || $0 == "," })
                        .map { $0.trimmingCharacters(in: .whitespaces) }
                        .filter { !$0.isEmpty }
                } else if let value = extractValue(trimmed, key: "forwardable") {
                    config.isForwardable = (value.lowercased() == "true"
                                            || value.lowercased() == "yes"
                                            || value == "1")
                }

            case "realms":
                // Realm names appear as "REALM.COM = {" lines
                if trimmed.contains("=") && trimmed.hasSuffix("{") {
                    let realmName = trimmed
                        .split(separator: "=").first?
                        .trimmingCharacters(in: .whitespaces) ?? ""
                    if !realmName.isEmpty {
                        realmNames.append(realmName)
                    }
                }

            default:
                break
            }
        }

        if !realmNames.isEmpty {
            config.realmNames = realmNames
        }

        return config
    }

    /// Extract value from a "key = value" line.
    private func extractValue(_ line: String, key: String) -> String? {
        let parts = line.split(separator: "=", maxSplits: 1)
        guard parts.count == 2 else { return nil }
        let lineKey = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
        guard lineKey == key.lowercased() else { return nil }
        var value = String(parts[1])
        // Strip inline comments (# or ;) — safe here because extractValue
        // is only called for key=value lines, never section headers.
        if let commentIdx = value.firstIndex(where: { $0 == "#" || $0 == ";" }) {
            value = String(value[value.startIndex..<commentIdx])
        }
        return value.trimmingCharacters(in: .whitespaces)
    }
}
