import Foundation

/// The user whose per-user files an assessment reads. Under `sudo`, macOS reports root's home
/// (`/var/root`) as the current user's, so the invoking user from `SUDO_USER` is used instead.
public enum AssessedUser {
    /// The assessed user's home: the `SUDO_USER`'s home when running as root under sudo, else the process home.
    public static func homeDirectory() -> URL {
        homeDirectory(
            effectiveUID: geteuid(),
            environment: ProcessInfo.processInfo.environment,
            lookup: passwdHome,
            fallback: FileManager.default.homeDirectoryForCurrentUser
        )
    }

    public static var homePath: String { homeDirectory().path }

    /// Pure rule behind `homeDirectory()`, with the process facts injected.
    public static func homeDirectory(
        effectiveUID: uid_t,
        environment: [String: String],
        lookup: (String) -> String?,
        fallback: URL
    ) -> URL {
        guard effectiveUID == 0,
              let user = environment["SUDO_USER"], !user.isEmpty, user != "root",
              let home = lookup(user), !home.isEmpty
        else { return fallback }
        return URL(fileURLWithPath: home, isDirectory: true)
    }

    /// The assessed user's ID: `SUDO_UID` when running as root under sudo, else the process user ID.
    public static func userID(
        effectiveUID: uid_t = geteuid(),
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> uid_t {
        guard effectiveUID == 0, let text = environment["SUDO_UID"], let uid = uid_t(text), uid != 0
        else { return getuid() }
        return uid
    }

    /// `pw_dir` for `user` from the password database (reentrant lookup; collectors run concurrently).
    public static func passwdHome(_ user: String) -> String? {
        var entry = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 4096)
        return buffer.withUnsafeMutableBufferPointer { storage -> String? in
            guard getpwnam_r(user, &entry, storage.baseAddress, storage.count, &result) == 0,
                  result != nil, let dir = entry.pw_dir
            else { return nil }
            return String(cString: dir)
        }
    }
}
