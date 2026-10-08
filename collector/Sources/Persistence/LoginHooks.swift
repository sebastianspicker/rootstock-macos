import Foundation
import HostCommand
import Models

/// Legacy loginwindow `LoginHook` / `LogoutHook` scripts, which run as root at login or logout.
extension PersistenceDataSource {
    /// A hook script configured in a loginwindow preferences plist.
    struct LoginHook: Equatable {
        let label: String
        let preferencesPath: String
        let program: String
    }

    static var loginWindowPreferencePaths: [String] {
        [
            "/Library/Preferences/com.apple.loginwindow.plist",
            NSHomeDirectory() + "/Library/Preferences/com.apple.loginwindow.plist",
        ]
    }

    func collectLoginHooks() -> [LaunchItem] {
        Self.loginWindowPreferencePaths.flatMap { path -> [LaunchItem] in
            guard let data = try? BoundedFileReader.read(path: path),
                  let dict = Shell.parsePlistDict(from: data) else { return [] }
            let modified = FileTimestamp.modified(path: path)
            return Self.loginHooks(from: dict, preferencesPath: path).map { hook in
                let facts = ProgramFacts(program: hook.program)
                return LaunchItem(
                    label: hook.label,
                    path: hook.preferencesPath,
                    type: .loginHook,
                    program: hook.program,
                    runAtLoad: true,
                    user: nil,
                    ownership: ownership(plistPath: hook.preferencesPath, program: hook.program),
                    details: LaunchItem.Details(
                        programExists: facts.exists,
                        programSha256: facts.sha256,
                        plistModified: modified
                    )
                )
            }
        }
    }

    /// Extract `LoginHook` and `LogoutHook` from a loginwindow preferences dictionary.
    static func loginHooks(from dict: [String: Any], preferencesPath: String) -> [LoginHook] {
        ["LoginHook", "LogoutHook"].compactMap { key in
            guard let program = (dict[key] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !program.isEmpty else { return nil }
            return LoginHook(label: "loginwindow.\(key)", preferencesPath: preferencesPath, program: program)
        }
    }
}
