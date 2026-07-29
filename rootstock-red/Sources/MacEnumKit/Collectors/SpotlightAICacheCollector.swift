import Foundation
import RootstockCore

/// Spotlight / mdworker / on-device AI-cache data-access class (Wave-8).
///
/// Research basis: Sploitlight-class Spotlight research; on-device AI cache path awareness.
/// Safety and behavior: typed `SpotlightAICacheState`; never dumps index, model, or user content.
public struct SpotlightAICacheCollector: Collector {
    public static let id = "collect.spotlight_ai_cache"
    public static let cost: CollectorCost = .low

    private static let spotlightPaths: [String] = [
        "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework",
        "/usr/bin/mdfind",
        "/usr/bin/mdls",
        "/usr/bin/mdutil",
        "/System/Library/LaunchDaemons/com.apple.metadata.mds.plist",
        "/System/Library/LaunchAgents/com.apple.mdworker.shared.plist",
        "/.Spotlight-V100",
        "/System/Volumes/Data/.Spotlight-V100",
        NSHomeDirectory() + "/Library/Metadata",
        NSHomeDirectory() + "/.Spotlight-V100",
    ]

    private static let metadataFrameworkPaths: [String] = [
        "/System/Library/Frameworks/CoreSpotlight.framework",
        "/System/Library/PrivateFrameworks/CoreSpotlightImportExtension.framework",
        "/System/Library/PrivateFrameworks/Spotlight.framework",
        "/System/Library/PrivateFrameworks/SpotlightDaemon.framework",
        "/System/Library/PrivateFrameworks/SpotlightIndex.framework",
        "/System/Library/PrivateFrameworks/SpotlightLinguistics.framework",
    ]

    private static let aiCachePathHints: [String] = [
        NSHomeDirectory() + "/Library/Caches",
        NSHomeDirectory() + "/Library/IntelligencePlatform",
        NSHomeDirectory() + "/Library/Application Support/AppleIntelligence",
        "/System/Library/PrivateFrameworks/AppleIntelligence.framework",
        "/System/Library/PrivateFrameworks/GenerativeModels.framework",
        "/System/Library/PrivateFrameworks/ModelCatalog.framework",
        "/System/Library/PrivateFrameworks/SiriAnalytics.framework",
        NSHomeDirectory() + "/Library/Application Support/Knowledge",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Spotlight/AI-cache surface: path presence only - never dumps index or model contents",
        ]

        var spotlight: [String] = []
        for path in Self.spotlightPaths where fm.fileExists(atPath: path) {
            spotlight.append(path)
            notes.append("spotlight_path: \(path)")
        }

        var metadata: [String] = []
        for path in Self.metadataFrameworkPaths where fm.fileExists(atPath: path) {
            metadata.append(path)
            notes.append("metadata_framework: \(path)")
        }

        var aiCache: [String] = []
        for path in Self.aiCachePathHints where fm.fileExists(atPath: path) {
            aiCache.append(path)
            notes.append("ai_cache_hint: \(path)")
        }

        spotlight = Array(Set(spotlight)).sorted()
        metadata = Array(Set(metadata)).sorted()
        aiCache = Array(Set(aiCache)).sorted()

        let surface = !spotlight.isEmpty || !metadata.isEmpty || !aiCache.isEmpty

        var state = CollectedState()
        state.spotlightAICache = SpotlightAICacheState(
            spotlightPaths: spotlight,
            metadataFrameworkPaths: metadata,
            aiCachePathHints: aiCache,
            dataAccessSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "spotlight=\(spotlight.count) metadata=\(metadata.count) "
            + "aiCache=\(aiCache.count) surface=\(surface)"
        return state
    }
}
