import Foundation
import Security

/// Reads the team and signing identifier of a launch item's program so the graph
/// can connect daemons and agents to the application that installed them even
/// when the program lives outside the app bundle (PrivilegedHelperTools,
/// Application Support, /usr/local/bin).
final class ProgramSigningIdentity: @unchecked Sendable {
    struct Identity: Sendable {
        let teamId: String?
        let signingId: String?
    }

    private let lock = NSLock()
    private var cache: [String: Identity?] = [:]

    /// Identity of the signed code at `path`, or nil when the program is unsigned,
    /// missing, or unreadable. Results are cached per path.
    func identity(forProgramAt path: String) -> Identity? {
        lock.lock()
        if let cached = cache[path] {
            lock.unlock()
            return cached
        }
        lock.unlock()
        let identity = Self.read(path: path)
        lock.lock()
        cache[path] = identity
        lock.unlock()
        return identity
    }

    private static func read(path: String) -> Identity? {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(
            URL(fileURLWithPath: path) as CFURL, SecCSFlags(rawValue: 0), &staticCode
        ) == errSecSuccess, let code = staticCode else {
            return nil
        }
        var cfInfo: CFDictionary?
        // kSecCSSigningInformation (0x2) exposes the team identifier.
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: 0x2), &cfInfo) == errSecSuccess,
              let info = cfInfo as? [String: Any] else {
            return nil
        }
        let signingId = info[kSecCodeInfoIdentifier as String] as? String
        let teamId = info[kSecCodeInfoTeamIdentifier as String] as? String
        guard signingId != nil || teamId != nil else { return nil }
        return Identity(teamId: teamId, signingId: signingId)
    }
}
