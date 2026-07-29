import Foundation
import Models

/// Scans installed MDM configuration profiles and extracts TCC policy payloads.
///
/// Uses `/usr/bin/profiles -C -o stdout-xml` (computer-level) and
/// `/usr/bin/profiles -L -o stdout-xml` (user-level).
/// Neither command requires root privileges for listing.
struct MDMProfileScanner {

    func scan() -> (profiles: [MDMProfile], errors: [String]) {
        var profiles: [MDMProfile] = []
        var errors: [String] = []

        // Computer-level profiles
        let (computerProfiles, computerErrors) = runProfiles(args: ["-C", "-o", "stdout-xml"])
        profiles.append(contentsOf: computerProfiles)
        errors.append(contentsOf: computerErrors)

        // User-level profiles (typically empty unless user profiles are installed)
        let (userProfiles, userErrors) = runProfiles(args: ["-L", "-o", "stdout-xml"])
        profiles.append(contentsOf: userProfiles)
        errors.append(contentsOf: userErrors)

        return (profiles, errors)
    }

    // MARK: - Private

    private func runProfiles(args: [String]) -> ([MDMProfile], [String]) {
        let profilesPath = "/usr/bin/profiles"
        guard FileManager.default.isExecutableFile(atPath: profilesPath) else {
            return ([], ["profiles command not available at \(profilesPath)"])
        }

        let outcome = Shell.execute(profilesPath, args, timeoutSeconds: 15)
        guard case .success(let result) = outcome else {
            return (
                [],
                ["profiles \(args.joined(separator: " ")) failed: \(outcome.failureDescription ?? "command failure")"]
            )
        }

        let data = Data(result.stdout.utf8)

        // Empty output = no profiles installed for this scope
        guard !data.isEmpty else { return ([], []) }

        return parseProfilesXML(data)
    }

    /// Parse the XML plist output from `profiles -C -o stdout-xml`.
    /// Internal (not private) so tests can call it directly with fixture data.
    func parseProfilesXML(_ data: Data) -> ([MDMProfile], [String]) {
        var format = PropertyListSerialization.PropertyListFormat.xml
        guard let plist = try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ), let dict = plist as? [String: Any] else {
            return ([], ["Failed to parse profiles plist output"])
        }

        var profiles: [MDMProfile] = []

        for scopeKey in ["_computerlevel", "_user"] {
            guard let profileArray = dict[scopeKey] as? [[String: Any]] else { continue }
            for profileDict in profileArray {
                if let profile = parseProfile(from: profileDict) {
                    profiles.append(profile)
                }
            }
        }

        return (profiles, [])
    }

    // MARK: - Profile parsing

    private func parseProfile(from dict: [String: Any]) -> MDMProfile? {
        guard let identifier = dict["ProfileIdentifier"] as? String,
              !identifier.isEmpty else { return nil }

        let displayName  = dict["ProfileDisplayName"] as? String ?? identifier
        let organization = dict["ProfileOrganization"] as? String
        let installDate  = dict["ProfileInstallDate"] as? String

        let tccPolicies = parseTCCPolicies(from: dict)

        return MDMProfile(
            identifier: identifier,
            displayName: displayName,
            organization: organization,
            installDate: installDate,
            tccPolicies: tccPolicies
        )
    }

    /// Extract TCC policies from a profile's PayloadItems array.
    private func parseTCCPolicies(from profileDict: [String: Any]) -> [TCCPolicy] {
        guard let payloadItems = profileDict["ProfileItems"] as? [[String: Any]] else {
            return []
        }

        return payloadItems.flatMap { item in
            tccServices(from: item).flatMap { service, entriesAny in
                policiesByService(service: service, entriesAny: entriesAny)
            }
        }
    }

    private func tccServices(from item: [String: Any]) -> [String: Any] {
        guard let payloadType = item["PayloadType"] as? String,
              payloadType == "com.apple.TCC.configuration-profile-policy",
              let payloadContent = item["PayloadContent"] as? [String: Any],
              let services = payloadContent["Services"] as? [String: Any] else {
            return [:]
        }
        return services
    }

    private func policiesByService(service: String, entriesAny: Any) -> [TCCPolicy] {
        guard let entries = entriesAny as? [[String: Any]] else { return [] }
        return entries.compactMap { policy(service: service, entry: $0) }
    }

    private func policy(service: String, entry: [String: Any]) -> TCCPolicy? {
        guard let identifier = entry["Identifier"] as? String,
              let identifierType = entry["IdentifierType"] as? String,
              identifierType == "bundleID" else {
            return nil
        }

        return TCCPolicy(
            service: service,
            clientBundleId: identifier,
            allowed: allowedValue(from: entry["Allowed"])
        )
    }

    private func allowedValue(from value: Any?) -> Bool {
        if let boolValue = value as? Bool {
            return boolValue
        }
        if let numberValue = value as? Int {
            return numberValue != 0
        }
        return false
    }
}
