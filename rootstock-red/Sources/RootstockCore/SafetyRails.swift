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

    /// Throws if kill switch is active.
    public static func ensureNotDisabled() throws {
        let url = killSwitchURL
        if FileManager.default.fileExists(atPath: url.path) {
            throw RootstockError.killSwitchActive(path: url.path)
        }
    }

    /// Assess mode must not open network unless explicitly allowed.
    public static func ensureNetworkAllowed(context: EvaluationContext) throws {
        if context.mode == .assess && !context.allowNetwork {
            throw RootstockError.networkNotAllowed
        }
    }

    /// Lab consent gate.
    public static func ensureLabConsent(context: EvaluationContext, policy: ConsentPolicy = .labDefault) throws {
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
