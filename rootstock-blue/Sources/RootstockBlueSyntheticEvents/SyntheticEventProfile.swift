/// Synthetic fixture-profile selection. This does not subscribe to Endpoint Security.
import Foundation
import RootstockBlueCore

public enum SyntheticProfileName: String, Codable, Sendable, CaseIterable {
    case triage
    case research
    case quiet
}

public struct SyntheticEventProfile: Codable, Sendable {
    public var name: SyntheticProfileName
    public var description: String
    public var eventTypes: [String]
    public var defaultMutePrefixes: [String]

    public init(
        name: SyntheticProfileName,
        description: String,
        eventTypes: [String],
        defaultMutePrefixes: [String] = []
    ) {
        self.name = name
        self.description = description
        self.eventTypes = eventTypes
        self.defaultMutePrefixes = defaultMutePrefixes
    }

    public static func builtin(_ name: SyntheticProfileName) -> SyntheticEventProfile {
        switch name {
        case .triage:
            return SyntheticEventProfile(
                name: .triage,
                description: "Synthetic triage fixtures: process, authentication, persistence, and protection labels",
                eventTypes: [
                    "NOTIFY_EXEC", "NOTIFY_FORK", "NOTIFY_EXIT",
                    "NOTIFY_AUTHENTICATION", "NOTIFY_OPENSSH_LOGIN", "NOTIFY_SUDO",
                    "NOTIFY_BTM_LAUNCH_ITEM_ADD", "NOTIFY_BTM_LAUNCH_ITEM_REMOVE",
                    "NOTIFY_XP_MALWARE_DETECTED", "NOTIFY_XP_MALWARE_REMEDIATED",
                    "NOTIFY_CREATE", "NOTIFY_RENAME", "NOTIFY_UNLINK",
                    "NOTIFY_TCC_MODIFY",
                ],
                defaultMutePrefixes: ["/System/", "/usr/libexec/"]
            )
        case .research:
            return SyntheticEventProfile(
                name: .research,
                description: "Synthetic research fixtures: broader event-label coverage for controlled sessions",
                eventTypes: [
                    "NOTIFY_EXEC", "NOTIFY_FORK", "NOTIFY_EXIT",
                    "NOTIFY_CREATE", "NOTIFY_OPEN", "NOTIFY_WRITE", "NOTIFY_CLOSE",
                    "NOTIFY_RENAME", "NOTIFY_UNLINK", "NOTIFY_LINK",
                    "NOTIFY_AUTHENTICATION", "NOTIFY_BTM_LAUNCH_ITEM_ADD",
                    "NOTIFY_XPC_CONNECT", "NOTIFY_TCC_MODIFY",
                    "NOTIFY_XP_MALWARE_DETECTED", "NOTIFY_GATEKEEPER_USER_OVERRIDE",
                    "NOTIFY_REMOTE_THREAD_CREATE", "NOTIFY_CS_INVALIDATED",
                ],
                defaultMutePrefixes: []
            )
        case .quiet:
            return SyntheticEventProfile(
                name: .quiet,
                description: "Synthetic quiet fixtures: process, persistence, and protection labels",
                eventTypes: [
                    "NOTIFY_EXEC", "NOTIFY_EXIT",
                    "NOTIFY_BTM_LAUNCH_ITEM_ADD",
                    "NOTIFY_XP_MALWARE_DETECTED",
                ],
                defaultMutePrefixes: ["/System/", "/usr/", "/bin/", "/sbin/"]
            )
        }
    }

    public static func load(from url: URL) throws -> SyntheticEventProfile {
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(SyntheticEventProfile.self, from: data)
    }
}
