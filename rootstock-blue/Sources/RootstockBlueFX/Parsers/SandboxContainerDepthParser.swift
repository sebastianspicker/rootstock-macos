/// App sandbox container residual depth markers (red↔blue pair).
/// Honesty: never breaks app sandbox or forges container entitlements.
public struct SandboxContainerDepthParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "SANDBOXCONTAINER", tier: .tier2, description: "Sandbox container depth markers"),
        fileStem: "sandbox_container_depth",
        fieldPrefix: "sbxctr",
        eventType: "sandbox.container",
        defaultRiskTag: "sandbox_surface",
        defaultNotes: "Sandbox container depth markers - never breaks app sandbox or forges container entitlements"
    )

    public init() {}
}
