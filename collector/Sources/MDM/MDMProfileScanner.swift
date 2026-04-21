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

        let process = Process()
        process.executableURL = URL(fileURLWithPath: profilesPath)
        process.arguments = args

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return ([], ["profiles \(args.joined(separator: " ")) failed: \(error)"])
        }

        let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()

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

        var policies: [TCCPolicy] = []

        for item in payloadItems {
            guard let payloadType = item["PayloadType"] as? String,
                  payloadType == "com.apple.TCC.configuration-profile-policy",
                  let payloadContent = item["PayloadContent"] as? [String: Any],
                  let services = payloadContent["Services"] as? [String: Any] else {
                continue
            }

            for (service, entriesAny) in services {
                guard let entries = entriesAny as? [[String: Any]] else { continue }
                for entry in entries {
                    guard let identifier = entry["Identifier"] as? String,
                          let identifierType = entry["IdentifierType"] as? String,
                          identifierType == "bundleID" else { continue }

                    // Allowed can be Bool (true/false) or Int (1/0) depending on plist encoding
                    let allowed: Bool
                    if let b = entry["Allowed"] as? Bool {
                        allowed = b
                    } else if let n = entry["Allowed"] as? Int {
                        allowed = n != 0
                    } else {
                        allowed = false
                    }

                    policies.append(TCCPolicy(
                        service: service,
                        clientBundleId: identifier,
                        allowed: allowed
                    ))
                }
            }
        }

        return policies
    }
}
