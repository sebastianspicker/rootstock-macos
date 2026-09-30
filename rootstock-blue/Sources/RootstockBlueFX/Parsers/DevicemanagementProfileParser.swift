public struct DevicemanagementProfileParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "MDMPROF", tier: .tier2, description: "Device management profile markers"),
        fileStem: "devicemanagement_profile",
        fieldPrefix: "mdmprof",
        eventType: "mdm.profile_depth",
        defaultRiskTag: "device_mgmt_surface",
        defaultNotes: "Device management profile markers - never installs configuration profiles or enrolls hosts in MDM"
    )

    public init() {}
}
