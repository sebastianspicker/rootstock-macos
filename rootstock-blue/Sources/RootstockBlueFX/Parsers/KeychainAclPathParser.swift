/// Keychain ACL path residual surface markers (red↔blue pair).
/// Honesty: never dumps keychain items, passwords, or private keys.
public struct KeychainAclPathParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "KEYCHAINACLPATH", tier: .tier2, description: "Keychain ACL path plane markers"),
        fileStem: "keychain_acl_path",
        fieldPrefix: "kcacl",
        eventType: "keychain.acl_path",
        defaultRiskTag: "keychain_acl_surface",
        defaultNotes: "Keychain ACL path plane markers - never dumps keychain items, passwords, or private keys"
    )

    public init() {}
}
