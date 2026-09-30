/// Dock persistent apps / recent items dual-use markers (red↔blue pair).
///
/// Honesty: never modifies Dock.plist or plants malicious Dock entries.
public struct DockPersistenceSurfaceParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "DOCKPERSIST", tier: .tier2, description: "Dock persistence dual-use surface markers"),
        fileStem: "dock_persistence_surface",
        fieldPrefix: "dock",
        eventType: "dock.persistence",
        defaultRiskTag: "dock_surface",
        defaultNotes: "Dock persistence dual-use markers - never modifies Dock.plist or plants malicious Dock entries",
        keys: .extended
    )

    public init() {}
}
