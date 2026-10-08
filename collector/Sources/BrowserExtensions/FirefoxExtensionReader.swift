import Foundation
import Models

/// Reads Firefox add-ons from `Profiles/<profile>/extensions.json`.
enum FirefoxExtensionReader {
    static let bundleId = "org.mozilla.firefox"
    static let skippedLocations: Set<String> = ["app-builtin", "app-system-defaults"]

    static func read(profilesRoot: String, access: BrowserFileAccess) -> BrowserReadResult {
        var result = BrowserReadResult()
        let profiles: [String]
        switch access.listDirectory(profilesRoot) {
        case .absent: return result
        case .failed(let message):
            result.errors.append("Cannot list Firefox profiles at \(profilesRoot): \(message)")
            return result
        case .entries(let names): profiles = names.filter { !$0.hasPrefix(".") }
        }
        for profile in profiles {
            let profileDir = "\(profilesRoot)/\(profile)"
            guard !access.isSymbolicLink(profileDir) else { continue }
            let path = "\(profileDir)/extensions.json"
            switch access.readFile(path, BrowserFileAccess.manifestLimit) {
            case .absent: continue
            case .failed(let message): result.errors.append("Cannot read \(path): \(message)")
            case .data(let data):
                guard let extensions = parseExtensionsJSON(data, profile: profile, profileDir: profileDir) else {
                    result.errors.append("Malformed Firefox extensions.json \(path)")
                    continue
                }
                result.extensions.append(contentsOf: extensions)
            }
        }
        return result
    }

    /// Parse `extensions.json`; nil when the document is malformed.
    static func parseExtensionsJSON(_ data: Data, profile: String, profileDir: String) -> [BrowserExtension]? {
        guard let document = BrowserExtensionFormat.jsonObject(data),
              let addons = document["addons"] as? [Any] else { return nil }
        return addons.compactMap { addon in
            (addon as? [String: Any]).flatMap { makeExtension($0, profile: profile, profileDir: profileDir) }
        }
    }

    static func makeExtension(_ addon: [String: Any], profile: String, profileDir: String) -> BrowserExtension? {
        guard addon["type"] as? String == "extension",
              let addonId = addon["id"] as? String,
              !skippedLocations.contains(addon["location"] as? String ?? "") else { return nil }
        let locale = addon["defaultLocale"] as? [String: Any]
        let permissions = addon["userPermissions"] as? [String: Any]
        return BrowserExtension(
            browser: .firefox,
            browserBundleId: bundleId,
            profile: profile,
            extensionId: addonId,
            name: locale?["name"] as? String ?? addonId,
            version: addon["version"] as? String ?? "",
            path: addon["path"] as? String ?? "\(profileDir)/extensions/\(addonId).xpi",
            manifest: BrowserExtension.Manifest(
                manifestVersion: (addon["manifestVersion"] as? NSNumber)?.intValue,
                permissions: BrowserExtensionFormat.strings(permissions?["permissions"]),
                hostPermissions: BrowserExtensionFormat.strings(permissions?["origins"])
            ),
            installation: installation(addon)
        )
    }

    static func installation(_ addon: [String: Any]) -> BrowserExtension.Installation {
        let fromWebstore = isFromAMO(addon["sourceURI"] as? String)
        let location = addon["location"] as? String
        let installLocation: BrowserExtension.InstallLocation
        if location == "app-profile" {
            installLocation = fromWebstore ? .webstore : .unknown
        } else {
            installLocation = location == nil ? .unknown : .external
        }
        return BrowserExtension.Installation(
            fromWebstore: fromWebstore,
            enabled: enabledState(addon),
            installTime: BrowserExtensionFormat.epochMillisecondsToISO8601(addon["installDate"]),
            installLocation: installLocation
        )
    }

    private static func enabledState(_ addon: [String: Any]) -> Bool? {
        guard let active = addon["active"] as? Bool else { return nil }
        return active && !(addon["userDisabled"] as? Bool ?? false)
    }

    static func isFromAMO(_ sourceURI: String?) -> Bool {
        guard let sourceURI, let host = URL(string: sourceURI)?.host else { return false }
        return host == "addons.mozilla.org"
    }
}
