public struct ContactsPathPlaneParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "CTPATH", tier: .tier2, description: "Contacts path plane markers"),
        fileStem: "contacts_path_plane",
        fieldPrefix: "ctpath",
        eventType: "contacts.path",
        defaultRiskTag: "contacts_surface",
        defaultNotes: "Contacts path plane markers - never exports contact cards or dumps AddressBook database contents"
    )

    public init() {}
}
