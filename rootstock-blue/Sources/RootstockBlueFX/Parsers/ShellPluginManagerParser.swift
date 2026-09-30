/// Shell plugin manager dual-use residual markers (red↔blue pair).
/// Honesty: never installs oh-my-zsh plugins or rewrites shell init for persistence.
public struct ShellPluginManagerParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "SHELLPLUGINMGR", tier: .tier2, description: "Shell plugin manager dual-use markers"),
        fileStem: "shell_plugin_manager",
        fieldPrefix: "shplug",
        eventType: "shell.plugin_manager",
        defaultRiskTag: "shell_plugin_surface",
        defaultNotes: "Shell plugin manager dual-use markers - never installs oh-my-zsh plugins or rewrites shell init for persistence"
    )

    public init() {}
}
