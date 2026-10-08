import Foundation

/// A persistence mechanism: launchd job, login item, cron job, or login hook.
public struct LaunchItem: GraphNode {
    public var nodeType: String { "LaunchItem" }

    /// Label or identifier for this persistence item (e.g., "com.apple.logd").
    public let label: String

    /// Path to the plist, crontab, or hook configuration file.
    public let path: String

    /// How this item achieves persistence.
    public let type: ItemType

    /// Binary or script that is executed.
    public let program: String?

    /// Whether the item starts automatically at boot or login.
    public let runAtLoad: Bool

    /// User account this item runs as (nil = inherits from context).
    public let user: String?

    /// Owner of the plist configuration file (e.g., "root").
    public let plistOwner: String?

    /// Owner of the program binary (e.g., "root").
    public let programOwner: String?

    /// Whether the plist file is writable by a non-root user.
    public let plistWritableByNonRoot: Bool

    /// Whether the program binary is writable by a non-root user.
    public let programWritableByNonRoot: Bool

    /// Team identifier of the program's code signature (nil when unsigned, Apple-signed, or unread).
    public let programTeamId: String?

    /// Signing identifier of the program's code signature (nil when unsigned or unread).
    public let programSigningId: String?

    /// `ProgramArguments` (at most 16 entries, each truncated to 256 characters).
    public let programArguments: [String]

    /// Sorted keys of `EnvironmentVariables`; values are never recorded.
    public let environmentVariableNames: [String]

    /// `EnvironmentVariables` entries whose key starts with `DYLD_`.
    public let dyldEnvironment: [String: String]

    /// Sorted launch triggers derived from the plist keys (e.g., "start_interval", "watch_paths").
    public let triggers: [String]

    /// `StartInterval` in seconds.
    public let intervalSeconds: Int?

    /// `LimitLoadToSessionType` (first element when an array).
    public let sessionType: String?

    /// `Disabled` key of the plist.
    public let disabled: Bool

    /// Whether launchd currently has the label loaded (nil when launchctl could not be consulted).
    public let loaded: Bool?

    /// Whether the program path exists on disk (nil when there is no program).
    public let programExists: Bool?

    /// Lower-case hex SHA-256 of the program file (nil when not hashed).
    public let programSha256: String?

    /// ISO 8601 UTC modification time of the plist, crontab, or hook source file.
    public let plistModified: String?

    /// Containing `.app` path for items embedded in an application bundle.
    public let bundlePath: String?

    public enum ItemType: String, Codable, Sendable {
        case daemon
        case agent
        case loginItem = "login_item"
        case cron
        case loginHook = "login_hook"
    }

    public struct Ownership: Codable, Sendable {
        public let plistOwner: String?
        public let programOwner: String?
        public let plistWritableByNonRoot: Bool
        public let programWritableByNonRoot: Bool
        public let programTeamId: String?
        public let programSigningId: String?

        public init(
            plistOwner: String? = nil,
            programOwner: String? = nil,
            plistWritableByNonRoot: Bool = false,
            programWritableByNonRoot: Bool = false,
            programTeamId: String? = nil,
            programSigningId: String? = nil
        ) {
            self.plistOwner = plistOwner
            self.programOwner = programOwner
            self.plistWritableByNonRoot = plistWritableByNonRoot
            self.programWritableByNonRoot = programWritableByNonRoot
            self.programTeamId = programTeamId
            self.programSigningId = programSigningId
        }
    }

    public struct Details: Codable, Sendable {
        public let programArguments: [String]
        public let environmentVariableNames: [String]
        public let dyldEnvironment: [String: String]
        public let triggers: [String]
        public let intervalSeconds: Int?
        public let sessionType: String?
        public let disabled: Bool
        public let loaded: Bool?
        public let programExists: Bool?
        public let programSha256: String?
        public let plistModified: String?
        public let bundlePath: String?

        public init(
            programArguments: [String] = [],
            environmentVariableNames: [String] = [],
            dyldEnvironment: [String: String] = [:],
            triggers: [String] = [],
            intervalSeconds: Int? = nil,
            sessionType: String? = nil,
            disabled: Bool = false,
            loaded: Bool? = nil,
            programExists: Bool? = nil,
            programSha256: String? = nil,
            plistModified: String? = nil,
            bundlePath: String? = nil
        ) {
            self.programArguments = programArguments
            self.environmentVariableNames = environmentVariableNames
            self.dyldEnvironment = dyldEnvironment
            self.triggers = triggers
            self.intervalSeconds = intervalSeconds
            self.sessionType = sessionType
            self.disabled = disabled
            self.loaded = loaded
            self.programExists = programExists
            self.programSha256 = programSha256
            self.plistModified = plistModified
            self.bundlePath = bundlePath
        }
    }

    public init(
        label: String,
        path: String,
        type: ItemType,
        program: String?,
        runAtLoad: Bool,
        user: String?,
        ownership: Ownership = Ownership(),
        details: Details = Details()
    ) {
        self.label = label
        self.path = path
        self.type = type
        self.program = program
        self.runAtLoad = runAtLoad
        self.user = user
        self.plistOwner = ownership.plistOwner
        self.programOwner = ownership.programOwner
        self.plistWritableByNonRoot = ownership.plistWritableByNonRoot
        self.programWritableByNonRoot = ownership.programWritableByNonRoot
        self.programTeamId = ownership.programTeamId
        self.programSigningId = ownership.programSigningId
        self.programArguments = details.programArguments
        self.environmentVariableNames = details.environmentVariableNames
        self.dyldEnvironment = details.dyldEnvironment
        self.triggers = details.triggers
        self.intervalSeconds = details.intervalSeconds
        self.sessionType = details.sessionType
        self.disabled = details.disabled
        self.loaded = details.loaded
        self.programExists = details.programExists
        self.programSha256 = details.programSha256
        self.plistModified = details.plistModified
        self.bundlePath = details.bundlePath
    }

    enum CodingKeys: String, CodingKey {
        case label
        case path
        case type
        case program
        case runAtLoad = "run_at_load"
        case user
        case plistOwner = "plist_owner"
        case programOwner = "program_owner"
        case plistWritableByNonRoot = "plist_writable_by_non_root"
        case programWritableByNonRoot = "program_writable_by_non_root"
        case programTeamId = "program_team_id"
        case programSigningId = "program_signing_id"
        case programArguments = "program_arguments"
        case environmentVariableNames = "environment_variable_names"
        case dyldEnvironment = "dyld_environment"
        case triggers
        case intervalSeconds = "interval_seconds"
        case sessionType = "session_type"
        case disabled
        case loaded
        case programExists = "program_exists"
        case programSha256 = "program_sha256"
        case plistModified = "plist_modified"
        case bundlePath = "bundle_path"
    }
}
