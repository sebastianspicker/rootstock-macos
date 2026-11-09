/// Fail-closed safety rails: kill switch, assess defaults, and lab consent enforcement.
import Foundation

/// Safety rails for assess-first defaults.
public enum SafetyRails: Sendable {
    /// Kill switch path: if this file exists, Rootstock Red refuses to run.
    public static var killSwitchURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".rootstock-red", isDirectory: true)
            .appendingPathComponent("DISABLE", isDirectory: false)
    }

    public static var rootstockConfigDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".rootstock-red", isDirectory: true)
    }

    /// Kill switch in the assessed (sudo-invoking) user's home; the same file as `killSwitchURL` without sudo.
    public static var assessedKillSwitchURL: URL {
        AssessedHome.url
            .appendingPathComponent(".rootstock-red", isDirectory: true)
            .appendingPathComponent("DISABLE", isDirectory: false)
    }

    /// Throws if the kill switch exists in either the process home or the assessed user's home.
    public static func ensureNotDisabled(
        killSwitchURL: URL = SafetyRails.killSwitchURL,
        assessedKillSwitchURL: URL = SafetyRails.assessedKillSwitchURL,
        fileManager: FileManager = .default
    ) throws {
        for url in [killSwitchURL, assessedKillSwitchURL] where fileManager.fileExists(atPath: url.path) {
            throw RootstockError.killSwitchActive(path: url.path)
        }
    }

    /// Lab consent gate.
    public static func ensureLabConsent(
        context: EvaluationContext,
        policy: ConsentPolicy = .labDefault,
        killSwitchURL: URL = SafetyRails.killSwitchURL,
        assessedKillSwitchURL: URL = SafetyRails.assessedKillSwitchURL,
        fileManager: FileManager = .default
    ) throws {
        try ensureNotDisabled(
            killSwitchURL: killSwitchURL,
            assessedKillSwitchURL: assessedKillSwitchURL,
            fileManager: fileManager
        )
        guard context.mode == .lab || context.mode == .purple else {
            throw RootstockError.unauthorized(reason: "lab/purple mode required")
        }
        guard context.consent.satisfies(policy) else {
            throw RootstockError.unauthorized(
                reason: "requires --i-am-authorized, --scope, --operator (and confirm if required)"
            )
        }
    }

    /// Ensure config directory exists for audit logs.
    public static func ensureConfigDirectory() throws {
        let dir = rootstockConfigDirectory
        if !FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
    }
}
