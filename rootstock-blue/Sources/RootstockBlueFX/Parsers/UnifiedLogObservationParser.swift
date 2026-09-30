/// Unified log / logarchive observation depth markers (red↔blue pair).
///
/// Honesty: never dumps private unified-log message bodies or force-collects other users' logarchives.
public struct UnifiedLogObservationParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "UNIFIEDLOGOBS", tier: .tier2, description: "Unified log observation surface markers"),
        fileStem: "unified_log_observation",
        fieldPrefix: "ulog",
        eventType: "unified_log.observation",
        defaultRiskTag: "observation_surface",
        defaultNotes: "Unified log observation markers - never dumps private unified-log message bodies or force-collects other users' logarchives",
        keys: .extended
    )

    public init() {}
}
