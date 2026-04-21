import Foundation

/// File permission metadata for a security-critical path.
///
/// Models the POSIX permissions, ownership, and extended ACL entries for files
/// like TCC databases, keychain files, sudoers configs, and LaunchDaemon plists
/// — the macOS equivalent of BloodHound's GenericAll/WriteDacl attack edges.
public struct FileACL: Codable, Sendable, GraphNode {
    public var nodeType: String { "FileACL" }

    /// Absolute filesystem path.
    public let path: String

    /// POSIX owner username.
    public let owner: String

    /// POSIX group name.
    public let group: String

    /// Octal mode string (e.g., "644", "755").
    public let mode: String

    /// Extended ACL entries, if any (e.g., "user:admin allow read,write").
    public let aclEntries: [String]

    /// Whether this path is protected by System Integrity Protection.
    public let isSipProtected: Bool

    /// Whether this file is writable by a non-root user (computed from mode + ACL).
    public let isWritableByNonRoot: Bool

    /// Semantic category for graph modeling.
    public let category: String

    public init(
        path: String,
        owner: String,
        group: String,
        mode: String,
        aclEntries: [String] = [],
        isSipProtected: Bool,
        isWritableByNonRoot: Bool,
        category: String
    ) {
        self.path = path
        self.owner = owner
        self.group = group
        self.mode = mode
        self.aclEntries = aclEntries
        self.isSipProtected = isSipProtected
        self.isWritableByNonRoot = isWritableByNonRoot
        self.category = category
    }

    enum CodingKeys: String, CodingKey {
        case path
        case owner
        case group
        case mode
        case aclEntries = "acl_entries"
        case isSipProtected = "is_sip_protected"
        case isWritableByNonRoot = "is_writable_by_non_root"
        case category
    }
}
