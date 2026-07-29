import Foundation
import RootstockCore

/// Notarization / stapling trust-depth surface (Wave-7).
///
/// Research basis: Gatekeeper/notarization research; spctl/stapler operator checklists.
/// Safety and behavior: typed `NotarizationStaplingState`; never forges tickets or bypasses GK.
public struct NotarizationStaplingCollector: Collector {
    public static let id = "collect.notarization_stapling"
    public static let cost: CollectorCost = .low

    private static let toolingPaths: [String] = [
        "/usr/bin/stapler",
        "/usr/sbin/spctl",
        "/usr/bin/codesign",
        "/usr/bin/xcrun",
        "/usr/bin/altool",
        "/usr/bin/notarytool",
    ]

    private static let ticketCacheHints: [String] = [
        "/Library/Caches/com.apple.cloudtelemetryd",
        "/var/db/gkopaque.bundle",
        "/Library/Preferences/com.apple.security.plist",
        "/var/db/SystemPolicyConfiguration",
        "/Library/Security/PolicyBanner.rtf",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fileManager = FileManager.default
        var notes: [String] = [
            "Notarization/stapling surface: tooling + path presence - no ticket forge, no GK bypass",
        ]
        let tooling = Self.toolingPaths.filter(fileManager.fileExists(atPath:))
        let caches = Self.ticketCacheHints.filter(fileManager.fileExists(atPath:))
        for path in tooling {
            notes.append("tooling: \(path)")
        }
        for path in caches {
            notes.append("ticket_or_policy_hint: \(path)")
        }

        let deliveryHints = Self.deliveryArtifactHints(fileManager: fileManager, notes: &notes)
        let assessmentToolsPresent = tooling.contains { $0.hasSuffix("spctl") || $0.hasSuffix("stapler") }

        var state = CollectedState()
        state.notarizationStapling = NotarizationStaplingState(
            toolingPaths: tooling.sorted(),
            ticketCacheHints: caches.sorted(),
            unstapledOrAdHocHints: deliveryHints,
            assessmentToolsPresent: assessmentToolsPresent,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "tools=\(tooling.count) caches=\(caches.count) "
            + "deliveryHints=\(deliveryHints.count) assessment=\(assessmentToolsPresent)"
        return state
    }

    private static func deliveryArtifactHints(
        fileManager: FileManager,
        notes: inout [String]
    ) -> [String] {
        let roots = [NSHomeDirectory() + "/Downloads", NSHomeDirectory() + "/Desktop"]
        let extensions = [".dmg", ".pkg", ".app", ".zip"]
        var hints: [String] = []

        for root in roots {
            guard let names = try? fileManager.contentsOfDirectory(atPath: root) else { continue }
            for name in names.prefix(20) where extensions.contains(where: name.hasSuffix) {
                let path = (root as NSString).appendingPathComponent(name)
                hints.append(path)
                notes.append("delivery_artifact_hint: \(path)")
            }
        }
        return Array(Set(hints)).sorted()
    }
}
