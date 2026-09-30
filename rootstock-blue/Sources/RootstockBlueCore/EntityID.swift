import Foundation

/// Stable entity identifiers for multi-source timeline merge
/// (ESF ↔ ULS ↔ FSEvents ↔ TCC ↔ parsers).
public enum EntityKind: String, Codable, Sendable, Hashable {
    case process
    case file
    case user
    case network
    case auth
    case persistence
    case tcc
    case host
}

public struct EntityID: Hashable, Codable, Sendable, CustomStringConvertible {
    public let kind: EntityKind
    public let value: String

    public init(kind: EntityKind, value: String) {
        self.kind = kind
        self.value = value
    }

    public var description: String { "\(kind.rawValue):\(value)" }

    public static func process(pid: Int32, startTime: Date? = nil, path: String? = nil) -> EntityID {
        var parts = ["pid=\(pid)"]
        if let startTime {
            parts.append("start=\(Int(startTime.timeIntervalSince1970))")
        }
        if let path {
            parts.append("path=\(path)")
        }
        return EntityID(kind: .process, value: parts.joined(separator: "|"))
    }

    public static func file(path: String) -> EntityID {
        EntityID(kind: .file, value: path)
    }

    public static func user(uid: uid_t? = nil, name: String? = nil) -> EntityID {
        if let name { return EntityID(kind: .user, value: "name=\(name)") }
        if let uid { return EntityID(kind: .user, value: "uid=\(uid)") }
        return EntityID(kind: .user, value: "unknown")
    }
}
