import Foundation

/// Type of Kerberos artifact found on the filesystem.
public enum KerberosArtifactType: String, Codable, Sendable {
    case ccache
    case keytab
    case config
}

/// Metadata about a Kerberos artifact (ccache, keytab, or config) found on disk.
///
/// **Security note:** Only filesystem metadata is collected — the file contents are
/// never read for ccache/keytab types.  For `config` type (`krb5.conf`), the file
/// IS read because it is a configuration file (not a credential store) and Apple
/// ships it world-readable.  The `principalHint` is inferred from the filename
/// pattern (`krb5cc_<uid>` → getpwuid), not from the credential cache itself.
public struct KerberosArtifact: Codable, Sendable, GraphNode {
    public var nodeType: String { "KerberosArtifact" }

    public let path: String
    public let artifactType: KerberosArtifactType
    public let owner: String?
    public let group: String?
    public let mode: String?
    public let modificationTime: String?
    public let principalHint: String?
    public let isReadable: Bool
    public let isWorldReadable: Bool
    public let isGroupReadable: Bool

    // krb5.conf parsed fields (config type only)
    public let defaultRealm: String?
    public let permittedEncTypes: [String]?
    public let realmNames: [String]?
    public let isForwardable: Bool?

    public init(
        path: String,
        artifactType: KerberosArtifactType,
        owner: String? = nil,
        group: String? = nil,
        mode: String? = nil,
        modificationTime: String? = nil,
        principalHint: String? = nil,
        isReadable: Bool = false,
        isWorldReadable: Bool = false,
        isGroupReadable: Bool = false,
        defaultRealm: String? = nil,
        permittedEncTypes: [String]? = nil,
        realmNames: [String]? = nil,
        isForwardable: Bool? = nil
    ) {
        self.path = path
        self.artifactType = artifactType
        self.owner = owner
        self.group = group
        self.mode = mode
        self.modificationTime = modificationTime
        self.principalHint = principalHint
        self.isReadable = isReadable
        self.isWorldReadable = isWorldReadable
        self.isGroupReadable = isGroupReadable
        self.defaultRealm = defaultRealm
        self.permittedEncTypes = permittedEncTypes
        self.realmNames = realmNames
        self.isForwardable = isForwardable
    }

    enum CodingKeys: String, CodingKey {
        case path
        case artifactType = "artifact_type"
        case owner
        case group
        case mode
        case modificationTime = "modification_time"
        case principalHint = "principal_hint"
        case isReadable = "is_readable"
        case isWorldReadable = "is_world_readable"
        case isGroupReadable = "is_group_readable"
        case defaultRealm = "default_realm"
        case permittedEncTypes = "permitted_enc_types"
        case realmNames = "realm_names"
        case isForwardable = "is_forwardable"
    }
}
