import Foundation
import Models

/// A Chromium-family browser and its profile root under `~/Library/Application Support/`.
struct ChromiumBrowser: Sendable {
    let browser: BrowserExtension.Browser
    let bundleId: String
    let relativeRoot: String

    static let all: [ChromiumBrowser] = [
        ChromiumBrowser(browser: .chrome, bundleId: "com.google.Chrome", relativeRoot: "Google/Chrome"),
        ChromiumBrowser(browser: .chromium, bundleId: "org.chromium.Chromium", relativeRoot: "Chromium"),
        ChromiumBrowser(browser: .brave, bundleId: "com.brave.Browser", relativeRoot: "BraveSoftware/Brave-Browser"),
        ChromiumBrowser(browser: .edge, bundleId: "com.microsoft.edgemac", relativeRoot: "Microsoft Edge"),
        ChromiumBrowser(browser: .vivaldi, bundleId: "com.vivaldi.Vivaldi", relativeRoot: "Vivaldi"),
        ChromiumBrowser(browser: .arc, bundleId: "company.thebrowser.Browser", relativeRoot: "Arc/User Data"),
        ChromiumBrowser(browser: .opera, bundleId: "com.operasoftware.Opera", relativeRoot: "com.operasoftware.Opera"),
    ]
}

/// Reads Chromium-family extensions from `<profile>/Extensions/<id>/<version>/manifest.json`
/// and their install state from `Secure Preferences` / `Preferences`.
enum ChromiumExtensionReader {
    /// Identifies one installed extension version while it is being read.
    struct Context {
        let browser: ChromiumBrowser
        let profile: String
        let extensionId: String
        let path: String
    }

    static func read(browser: ChromiumBrowser, root: String, access: BrowserFileAccess) -> BrowserReadResult {
        var result = BrowserReadResult()
        let entries: [String]
        switch access.listDirectory(root) {
        case .absent: return result
        case .failed(let message):
            result.errors.append("Cannot list \(browser.browser.rawValue) profiles at \(root): \(message)")
            return result
        case .entries(let names): entries = names
        }
        for profile in profileNames(entries) {
            let profileDir = profile.isEmpty ? root : "\(root)/\(profile)"
            result.append(readProfile(browser: browser, profile: profile, profileDir: profileDir, access: access))
        }
        return result
    }

    /// `Default` and `Profile N`; a root that holds `Extensions` itself (Opera) is profile `""`.
    static func profileNames(_ entries: [String]) -> [String] {
        let profiles = entries.filter { $0 == "Default" || $0.hasPrefix("Profile ") }.sorted()
        return entries.contains("Extensions") ? [""] + profiles : profiles
    }

    private static func readProfile(
        browser: ChromiumBrowser,
        profile: String,
        profileDir: String,
        access: BrowserFileAccess
    ) -> BrowserReadResult {
        var result = BrowserReadResult()
        let extensionsDir = "\(profileDir)/Extensions"
        guard case .entries(let ids) = listing(extensionsDir, access: access, errors: &result.errors) else {
            return result
        }
        let settings = loadSettings(profileDir: profileDir, access: access, errors: &result.errors)
        for extensionId in ids where isExtensionId(extensionId) {
            let idDir = "\(extensionsDir)/\(extensionId)"
            guard !access.isSymbolicLink(idDir),
                  case .entries(let versions) = listing(idDir, access: access, errors: &result.errors),
                  let version = newestVersion(versions.filter { !access.isSymbolicLink("\(idDir)/\($0)") })
            else { continue }
            let context = Context(browser: browser, profile: profile, extensionId: extensionId, path: "\(idDir)/\(version)")
            switch readExtension(context, settings: settings[extensionId], access: access) {
            case .success(let item): result.extensions.append(item)
            case .failure(let failure): result.errors.append(failure.message)
            }
        }
        return result
    }

    struct ReadFailure: Error {
        let message: String
    }

    private static func readExtension(
        _ context: Context,
        settings: [String: Any]?,
        access: BrowserFileAccess
    ) -> Result<BrowserExtension, ReadFailure> {
        let manifestPath = "\(context.path)/manifest.json"
        guard case .data(let data) = access.readFile(manifestPath, BrowserFileAccess.manifestLimit) else {
            return .failure(ReadFailure(message: "Cannot read extension manifest \(manifestPath)"))
        }
        guard let manifest = BrowserExtensionFormat.jsonObject(data) else {
            return .failure(ReadFailure(message: "Malformed extension manifest \(manifestPath)"))
        }
        let messages = loadMessages(manifest: manifest, versionDir: context.path, access: access)
        return .success(makeExtension(manifest: manifest, messages: messages, settings: settings, context: context))
    }

    static func makeExtension(
        manifest: [String: Any],
        messages: [String: Any]?,
        settings: [String: Any]?,
        context: Context
    ) -> BrowserExtension {
        let rawName = manifest["name"] as? String ?? context.extensionId
        return BrowserExtension(
            browser: context.browser.browser,
            browserBundleId: context.browser.bundleId,
            profile: context.profile,
            extensionId: context.extensionId,
            name: resolveMessage(rawName, messages: messages),
            version: manifest["version"] as? String ?? "",
            path: context.path,
            manifest: manifestCapabilities(manifest),
            installation: installation(settings: settings)
        )
    }

    static func manifestCapabilities(_ manifest: [String: Any]) -> BrowserExtension.Manifest {
        let declared = BrowserExtensionFormat.strings(manifest["permissions"])
        let hosts = BrowserExtensionFormat.strings(manifest["host_permissions"])
            + declared.filter(BrowserExtensionFormat.isHostPattern)
        return BrowserExtension.Manifest(
            manifestVersion: (manifest["manifest_version"] as? NSNumber)?.intValue,
            permissions: declared.filter { !BrowserExtensionFormat.isHostPattern($0) },
            hostPermissions: deduplicated(hosts)
        )
    }

    static func installation(settings: [String: Any]?) -> BrowserExtension.Installation {
        guard let settings else { return BrowserExtension.Installation() }
        let fromWebstore = settings["from_webstore"] as? Bool
        return BrowserExtension.Installation(
            fromWebstore: fromWebstore,
            enabled: enabledState(settings),
            installTime: BrowserExtensionFormat.webKitTimeToISO8601(settings["install_time"]),
            installLocation: installLocation(code: (settings["location"] as? NSNumber)?.intValue, fromWebstore: fromWebstore)
        )
    }

    /// `state == 1` is enabled; newer Chromium drops `state` and records `disable_reasons` instead.
    private static func enabledState(_ settings: [String: Any]) -> Bool? {
        if let state = settings["state"] as? NSNumber { return state.intValue == 1 }
        if let reasons = settings["disable_reasons"] as? [Any] { return reasons.isEmpty }
        if let reasons = settings["disable_reasons"] as? NSNumber { return reasons.intValue == 0 }
        return nil
    }

    static func installLocation(code: Int?, fromWebstore: Bool?) -> BrowserExtension.InstallLocation {
        switch code {
        case 1: return fromWebstore == true ? .webstore : .unknown
        case 4: return .unpacked
        case 2, 3, 5, 6: return .external
        case 9, 11: return .policy
        case 10: return .component
        default: return .unknown
        }
    }

    /// `extensions.settings` from a Chromium preferences document.
    static func extensionSettings(fromPreferences data: Data) -> [String: [String: Any]]? {
        guard let document = BrowserExtensionFormat.jsonObject(data) else { return nil }
        let extensions = document["extensions"] as? [String: Any]
        let settings = extensions?["settings"] as? [String: Any] ?? [:]
        return settings.compactMapValues { $0 as? [String: Any] }
    }

    /// `Secure Preferences` wins; `Preferences` fills in extensions it does not list.
    private static func loadSettings(
        profileDir: String,
        access: BrowserFileAccess,
        errors: inout [String]
    ) -> [String: [String: Any]] {
        var merged: [String: [String: Any]] = [:]
        for file in ["Secure Preferences", "Preferences"] {
            let path = "\(profileDir)/\(file)"
            switch access.readFile(path, BrowserFileAccess.preferencesLimit) {
            case .absent: continue
            case .failed(let message): errors.append("Cannot read \(path): \(message)")
            case .data(let data):
                guard let settings = extensionSettings(fromPreferences: data) else {
                    errors.append("Malformed browser preferences \(path)")
                    continue
                }
                merged.merge(settings) { existing, _ in existing }
            }
        }
        return merged
    }

    /// Resolve `__MSG_<key>__` from `messages.json` (keys are case-insensitive).
    static func resolveMessage(_ raw: String, messages: [String: Any]?) -> String {
        guard raw.hasPrefix("__MSG_"), raw.hasSuffix("__"), raw.count > 8, let messages else { return raw }
        let key = String(raw.dropFirst(6).dropLast(2)).lowercased()
        let entry = messages.first { $0.key.lowercased() == key }?.value as? [String: Any]
        guard let message = entry?["message"] as? String, !message.isEmpty else { return raw }
        return message
    }

    private static func loadMessages(
        manifest: [String: Any],
        versionDir: String,
        access: BrowserFileAccess
    ) -> [String: Any]? {
        guard let name = manifest["name"] as? String, name.hasPrefix("__MSG_") else { return nil }
        let preferred = (manifest["default_locale"] as? String).flatMap { isLocaleName($0) ? $0 : nil } ?? "en"
        for locale in deduplicated([preferred, "en"]) {
            let path = "\(versionDir)/_locales/\(locale)/messages.json"
            if case .data(let data) = access.readFile(path, BrowserFileAccess.manifestLimit),
               let messages = BrowserExtensionFormat.jsonObject(data) {
                return messages
            }
        }
        return nil
    }

    /// `default_locale` names a directory under `_locales`; only plain locale tags
    /// (`^[A-Za-z0-9_-]{1,32}$`) are accepted so the value cannot leave the extension directory.
    static func isLocaleName(_ name: String) -> Bool {
        (1...32).contains(name.unicodeScalars.count) && name.unicodeScalars.allSatisfy { scalar in
            scalar.isASCII && (CharacterSet.alphanumerics.contains(scalar) || scalar == "_" || scalar == "-")
        }
    }

    /// Chromium extension ids are 32 characters in `a`–`p`.
    static func isExtensionId(_ name: String) -> Bool {
        name.count == 32 && name.allSatisfy { ("a"..."p").contains($0) }
    }

    /// Newest version directory by numeric component comparison (`1.10.0_0` > `1.9.2_0`).
    static func newestVersion(_ names: [String]) -> String? {
        names.filter { !$0.hasPrefix(".") }.max { versionComponents($0).lexicographicallyPrecedes(versionComponents($1)) }
    }

    private static func versionComponents(_ name: String) -> [Int] {
        name.split { $0 == "." || $0 == "_" }.map { Int($0) ?? 0 }
    }

    private static func listing(_ path: String, access: BrowserFileAccess, errors: inout [String]) -> DirectoryListing {
        let result = access.listDirectory(path)
        if case .failed(let message) = result {
            errors.append("Cannot list \(path): \(message)")
        }
        return result
    }

    private static func deduplicated(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}
