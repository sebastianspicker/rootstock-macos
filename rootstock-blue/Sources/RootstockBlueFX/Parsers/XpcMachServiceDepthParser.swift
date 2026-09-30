/// XPC Mach service residual depth markers (red↔blue pair).
/// Honesty: never registers XPC services or injects into Mach ports.
public struct XpcMachServiceDepthParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "XPCMACHSERVICE", tier: .tier2, description: "XPC Mach service depth markers"),
        fileStem: "xpc_mach_service_depth",
        fieldPrefix: "xpcmach",
        eventType: "xpc.mach_service",
        defaultRiskTag: "xpc_mach_surface",
        defaultNotes: "XPC Mach service depth markers - never registers XPC services or injects into Mach ports"
    )

    public init() {}
}
