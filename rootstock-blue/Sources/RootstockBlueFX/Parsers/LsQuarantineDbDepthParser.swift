/// LaunchServices QuarantineEvents DB residual depth markers (red↔blue pair).
/// Honesty: never deletes QuarantineEvents rows or clears LS quarantine history.
public struct LsQuarantineDbDepthParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "LSQUARANTINEDB", tier: .tier2, description: "LS QuarantineEvents depth markers"),
        fileStem: "ls_quarantine_db_depth",
        fieldPrefix: "lsqdb",
        eventType: "ls.quarantine_db",
        defaultRiskTag: "quarantine_db_surface",
        defaultNotes: "LS QuarantineEvents depth markers - never deletes QuarantineEvents rows or clears LS quarantine history"
    )

    public init() {}
}
