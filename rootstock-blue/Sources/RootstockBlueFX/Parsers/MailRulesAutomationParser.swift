/// Mail rules / Apple Mail automation persistence markers (red↔blue pair).
///
/// Honesty: never reads Mail contents or modifies user Mail rules.
public struct MailRulesAutomationParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "MAILRULESAUTO", tier: .tier2, description: "Mail rules automation surface markers"),
        fileStem: "mail_rules_automation",
        fieldPrefix: "mail_rules",
        eventType: "mail.rules",
        defaultRiskTag: "rules_surface",
        defaultNotes: "Mail rules automation markers - never reads Mail contents or modifies user Mail rules",
        keys: .extended
    )

    public init() {}
}
