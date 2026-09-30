/// Time Machine local snapshot residual depth markers (red↔blue pair).
/// Honesty: never mounts snapshots for data theft or deletes backup catalogs.
public struct TmLocalSnapshotDepthParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "TMLOCALSNAPSHOT", tier: .tier2, description: "TM local snapshot depth markers"),
        fileStem: "tm_local_snapshot_depth",
        fieldPrefix: "tmsnap",
        eventType: "tm.local_snapshot",
        defaultRiskTag: "tm_snapshot_surface",
        defaultNotes: "TM local snapshot depth markers - never mounts snapshots for data theft or deletes backup catalogs"
    )

    public init() {}
}
