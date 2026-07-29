import Foundation
import RootstockCore

/// MDM profile shallow parse depth (Wave-9).
///
/// Research basis: Configuration Profile PayloadType taxonomy; enterprise mobileconfig research.
/// Safety and behavior: shallow PayloadType / PayloadDisplayName inventory only; never dumps secrets or installs profiles.
public struct MDMProfileParseDepthCollector: Collector {
    public static let id = "collect.mdm_profile_parse_depth"
    public static let cost: CollectorCost = .low

    private static let searchRoots: [String] = [
        NSHomeDirectory() + "/Downloads",
        NSHomeDirectory() + "/Desktop",
        NSHomeDirectory() + "/Documents",
        "/Library/Managed Preferences",
        "/var/db/ConfigurationProfiles",
        "/Library/ConfigurationProfiles",
    ]

    private static let secretKeyHints: Set<String> = [
        "password", "Password", "PayloadContent", "PasswordHash",
        "SharedSecret", "PrivateKey", "privateKey", "Certificate",
        "PayloadCertificateFileName", "PasswordData", "EAPClientConfiguration",
    ]

    private struct ProfileEvidence {
        var examinedPaths: [String] = []
        var payloadTypes = Set<String>()
        var parsedCount = 0
        var displayNamePresent = false
    }

    private struct PayloadDetails {
        let types: Set<String>
        let displayNamePresent: Bool
    }

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "MDM profile parse depth: shallow PayloadType inventory only - never dumps secrets, never installs profiles",
        ]

        let candidates = discoverProfiles(fm, notes: &notes)
        let evidence = profileEvidence(candidates, fm: fm, notes: &notes)
        return collectedState(evidence: evidence, notes: notes)
    }

    private func discoverProfiles(_ fm: FileManager, notes: inout [String]) -> [String] {
        var candidates: [String] = []
        for root in Self.searchRoots where fm.fileExists(atPath: root) {
            candidates.append(contentsOf: mobileConfigPaths(in: root, fm: fm))
            recordProfileRoot(root, notes: &notes)
        }
        return Array(Set(candidates)).sorted().prefix(12).map { $0 }
    }

    private func mobileConfigPaths(in root: String, fm: FileManager) -> [String] {
        guard let entries = try? fm.contentsOfDirectory(atPath: root) else { return [] }
        return entries
            .filter { $0.lowercased().hasSuffix(".mobileconfig") }
            .map { (root as NSString).appendingPathComponent($0) }
    }

    private func recordProfileRoot(_ root: String, notes: inout [String]) {
        guard root.contains("ConfigurationProfiles") || root.contains("Managed Preferences") else { return }
        notes.append("profile_root: \(root)")
    }

    private func profileEvidence(
        _ candidates: [String],
        fm: FileManager,
        notes: inout [String]
    ) -> ProfileEvidence {
        var evidence = ProfileEvidence()
        for path in candidates {
            evidence.examinedPaths.append(path)
            guard let details = parseProfile(path, fm: fm, notes: &notes) else { continue }
            evidence.parsedCount += 1
            evidence.payloadTypes.formUnion(details.types)
            evidence.displayNamePresent = evidence.displayNamePresent || details.displayNamePresent
            notes.append("parsed_profile: \(path) types≈\(evidence.payloadTypes.count)")
        }
        return evidence
    }

    private func parseProfile(
        _ path: String,
        fm _: FileManager,
        notes: inout [String]
    ) -> PayloadDetails? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe]) else {
            notes.append("unreadable_profile: \(path)")
            return nil
        }
        guard data.count <= 512_000 else {
            notes.append("skipped_large_profile: \(path) size=\(data.count)")
            return nil
        }
        guard let plist = propertyList(from: data) else {
            notes.append("unparseable_profile: \(path)")
            return nil
        }
        return payloadDetails(in: plist, path: path, notes: &notes)
    }

    private func propertyList(from data: Data) -> [String: Any]? {
        var format = PropertyListSerialization.PropertyListFormat.xml
        return try? PropertyListSerialization.propertyList(
            from: data,
            options: [.mutableContainers],
            format: &format
        ) as? [String: Any]
    }

    private func payloadDetails(
        in plist: [String: Any],
        path: String,
        notes: inout [String]
    ) -> PayloadDetails {
        var types = payloadTypes(in: plist)
        var displayNamePresent = hasDisplayName(in: plist)
        for item in nestedPayloads(in: plist) {
            types.formUnion(payloadTypes(in: item))
            displayNamePresent = displayNamePresent || hasDisplayName(in: item)
            recordSecretShapedKeys(in: item, path: path, notes: &notes)
        }
        return PayloadDetails(types: types, displayNamePresent: displayNamePresent)
    }

    private func payloadTypes(in payload: [String: Any]) -> Set<String> {
        guard let type = payload["PayloadType"] as? String else { return [] }
        return [type]
    }

    private func hasDisplayName(in payload: [String: Any]) -> Bool {
        payload["PayloadDisplayName"] != nil
    }

    private func nestedPayloads(in plist: [String: Any]) -> [[String: Any]] {
        plist["PayloadContent"] as? [[String: Any]] ?? []
    }

    private func recordSecretShapedKeys(
        in payload: [String: Any],
        path: String,
        notes: inout [String]
    ) {
        for key in payload.keys where Self.secretKeyHints.contains(key) {
            notes.append("secret_shaped_key_present_not_dumped: \(key) in \(path)")
        }
    }

    private func collectedState(evidence: ProfileEvidence, notes: [String]) -> CollectedState {
        let types = evidence.payloadTypes.sorted()
        let surface = evidence.parsedCount > 0 || !evidence.examinedPaths.isEmpty
            || notes.contains(where: { $0.hasPrefix("profile_root:") })
        var state = CollectedState()
        state.mdmProfileParseDepth = MDMProfileParseDepthState(
            examinedProfilePaths: evidence.examinedPaths,
            payloadTypes: types,
            parsedProfileCount: evidence.parsedCount,
            displayNamePresent: evidence.displayNamePresent,
            parseSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] = collectorNote(evidence: evidence, types: types, surface: surface)
        return state
    }

    private func collectorNote(evidence: ProfileEvidence, types: [String], surface: Bool) -> String {
        "examined=\(evidence.examinedPaths.count) parsed=\(evidence.parsedCount) types=\(types.count) "
            + "displayName=\(evidence.displayNamePresent) surface=\(surface)"
    }
}
