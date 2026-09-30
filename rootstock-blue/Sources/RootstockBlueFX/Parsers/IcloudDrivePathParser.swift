/// iCloud Drive / Mobile Documents path plane markers (red↔blue pair).
/// Honesty: never enumerates iCloud file contents or exfiltrates Mobile Documents.
public struct IcloudDrivePathParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "ICLOUDDRIVEPATH", tier: .tier2, description: "iCloud Drive path plane markers"),
        fileStem: "icloud_drive_path",
        fieldPrefix: "icldrv",
        eventType: "icloud.drive_path",
        defaultRiskTag: "icloud_path_surface",
        defaultNotes: "iCloud Drive path plane markers - never enumerates iCloud file contents or exfiltrates Mobile Documents"
    )

    public init() {}
}
