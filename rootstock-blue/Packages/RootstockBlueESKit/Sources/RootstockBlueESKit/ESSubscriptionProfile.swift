/// ESSubscriptionProfile - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public enum ESProfileName: String, Codable, Sendable, CaseIterable {
    case ir
    case research
    case quiet
}

public struct ESSubscriptionProfile: Codable, Sendable {
    public var name: ESProfileName
    public var description: String
    public var eventTypes: [String]
    public var authMode: Bool
    public var defaultMutePrefixes: [String]

    public init(
        name: ESProfileName,
        description: String,
        eventTypes: [String],
        authMode: Bool = false,
        defaultMutePrefixes: [String] = []
    ) {
        self.name = name
        self.description = description
        self.eventTypes = eventTypes
        // Auth/block never default on.
        self.authMode = authMode && !NonGoals.authBlockDefaultOn
        self.defaultMutePrefixes = defaultMutePrefixes
    }

    public static func builtin(_ name: ESProfileName) -> ESSubscriptionProfile {
        switch name {
        case .ir:
            return ESSubscriptionProfile(
                name: .ir,
                description: "IR triage: process, auth, BTM, XProtect; limited file",
                eventTypes: [
                    "NOTIFY_EXEC", "NOTIFY_FORK", "NOTIFY_EXIT",
                    "NOTIFY_AUTHENTICATION", "NOTIFY_OPENSSH_LOGIN", "NOTIFY_SUDO",
                    "NOTIFY_BTM_LAUNCH_ITEM_ADD", "NOTIFY_BTM_LAUNCH_ITEM_REMOVE",
                    "NOTIFY_XP_MALWARE_DETECTED", "NOTIFY_XP_MALWARE_REMEDIATED",
                    "NOTIFY_CREATE", "NOTIFY_RENAME", "NOTIFY_UNLINK",
                    "NOTIFY_TCC_MODIFY",
                ],
                authMode: false,
                defaultMutePrefixes: ["/System/", "/usr/libexec/"]
            )
        case .research:
            return ESSubscriptionProfile(
                name: .research,
                description: "Research: broader ES for detonation sessions",
                eventTypes: [
                    "NOTIFY_EXEC", "NOTIFY_FORK", "NOTIFY_EXIT",
                    "NOTIFY_CREATE", "NOTIFY_OPEN", "NOTIFY_WRITE", "NOTIFY_CLOSE",
                    "NOTIFY_RENAME", "NOTIFY_UNLINK", "NOTIFY_LINK",
                    "NOTIFY_AUTHENTICATION", "NOTIFY_BTM_LAUNCH_ITEM_ADD",
                    "NOTIFY_XPC_CONNECT", "NOTIFY_TCC_MODIFY",
                    "NOTIFY_XP_MALWARE_DETECTED", "NOTIFY_GATEKEEPER_USER_OVERRIDE",
                    "NOTIFY_REMOTE_THREAD_CREATE", "NOTIFY_CS_INVALIDATED",
                ],
                authMode: false,
                defaultMutePrefixes: []
            )
        case .quiet:
            return ESSubscriptionProfile(
                name: .quiet,
                description: "Quiet: process + persistence + XProtect only",
                eventTypes: [
                    "NOTIFY_EXEC", "NOTIFY_EXIT",
                    "NOTIFY_BTM_LAUNCH_ITEM_ADD",
                    "NOTIFY_XP_MALWARE_DETECTED",
                ],
                authMode: false,
                defaultMutePrefixes: ["/System/", "/usr/", "/bin/", "/sbin/"]
            )
        }
    }

    public static func load(from url: URL) throws -> ESSubscriptionProfile {
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(ESSubscriptionProfile.self, from: data)
    }
}
