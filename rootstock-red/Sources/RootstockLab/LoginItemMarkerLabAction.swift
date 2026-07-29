import Foundation
import RootstockCore

/// Lab login-item / SMAppService-adjacent marker - reversible plist under a lab directory.
///
/// Research basis: PersistentJXA login-item techniques; modern SMAppService persistence catalog.
/// Safety and behavior: no real SMAppService registration API abuse by default; FileManager marker only;
/// BTM honesty in cleanup notes; consent + dry-run default.
public struct LoginItemMarkerLabAction: LabAction {
    public static let id = "lab.persist.loginitem_marker"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let defaultLabel = "com.rootstock.red.lab.loginitem"
    public static let btmNote = """
    BTM honesty: even a lab marker plist may be user-visible if registered as a Login Item / \
    Background Item. Prefer lab directories over production LoginItems folders. Deleting the \
    marker does not guarantee BTM UI residual is cleared.
    """

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)

        let labRoot = Self.resolveLabRoot(params: request.parameters)
        let label = try Self.resolveLabel(params: request.parameters)
        let markerURL = labRoot
            .appendingPathComponent("login-items", isDirectory: true)
            .appendingPathComponent("\(label).marker.plist")

        switch request.operation {
        case .plan:
            return plan(markerURL: markerURL, label: label, dryRun: true)
        case .install:
            return try apply(markerURL: markerURL, label: label, dryRun: context.dryRun)
        case .status:
            return status(markerURL: markerURL, label: label)
        case .remove:
            return try remove(markerURL: markerURL, label: label, dryRun: context.dryRun)
        }
    }

    private func plan(markerURL: URL, label: String, dryRun: Bool) -> ActionResult {
        let steps = [
            "Lab login-item marker path: \(markerURL.path)",
            "Label=\(label) - technique marker only (not SMAppService.register)",
            "Do not call ServiceManagement / sfltool to force user-visible login items",
            Self.btmNote,
        ]
        return ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Dry-run login-item plan: would plant reversible marker for \(label) at \
            \(markerURL.path). No SMAppService registration; BTM residual risk if later loaded.
            """,
            dryRun: dryRun,
            plannedSteps: steps,
            cleanupNotes: [
                "Delete \(markerURL.path)",
                Self.btmNote,
            ],
            artifacts: [markerURL.path]
        )
    }

    private func apply(markerURL: URL, label: String, dryRun: Bool) throws -> ActionResult {
        let steps = [
            "Create parent dirs under lab root",
            "Write marker plist for \(label) (harmless ProgramArguments=/usr/bin/true)",
            "Skip SMAppService / login-item UI registration APIs",
        ]
        let cleanup = ["Delete \(markerURL.path)", Self.btmNote]

        if dryRun {
            return ActionResult(
                actionId: Self.id,
                success: true,
                message: "Dry-run: would write login-item marker at \(markerURL.path)",
                dryRun: true,
                plannedSteps: steps,
                cleanupNotes: cleanup,
                artifacts: [markerURL.path]
            )
        }

        let fm = FileManager.default
        try fm.createDirectory(
            at: markerURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let dict: [String: Any] = [
            "Label": label,
            "ProgramArguments": ["/usr/bin/true", "rootstock-red-lab-loginitem-marker"],
            "RunAtLoad": false,
            "RootstockRedLab": true,
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: dict,
            format: .xml,
            options: 0
        )
        try data.write(to: markerURL, options: .atomic)

        return ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Planted login-item technique marker for \(label) at \(markerURL.path) \
            (not registered via SMAppService).
            """,
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: cleanup,
            artifacts: [markerURL.path]
        )
    }

    private func status(markerURL: URL, label: String) -> ActionResult {
        let exists = LabMarkerLifecycle.markerExists(at: markerURL)
        return ActionResult(
            actionId: Self.id,
            success: true,
            message: exists
                ? "Login-item marker present for \(label) at \(markerURL.path)"
                : "Login-item marker absent for \(label) at \(markerURL.path)",
            dryRun: false,
            plannedSteps: ["Check marker exists: \(exists)"],
            cleanupNotes: exists ? [Self.btmNote] : ["No marker artifact"],
            artifacts: exists ? [markerURL.path] : []
        )
    }

    private func remove(markerURL: URL, label: String, dryRun: Bool) throws -> ActionResult {
        let exists = LabMarkerLifecycle.markerExists(at: markerURL)
        let steps = ["Delete marker if present: \(markerURL.path)"]

        if dryRun {
            return ActionResult(
                actionId: Self.id,
                success: true,
                message: "Dry-run: would delete login-item marker for \(label) (exists=\(exists))",
                dryRun: true,
                plannedSteps: steps,
                cleanupNotes: [Self.btmNote],
                artifacts: exists ? [markerURL.path] : []
            )
        }

        if exists {
            try LabMarkerLifecycle.removeMarker(at: markerURL)
        }
        return ActionResult(
            actionId: Self.id,
            success: true,
            message: "Removed login-item marker for \(label) (wasPresent=\(exists))",
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: [Self.btmNote],
            artifacts: exists ? [markerURL.path] : []
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }

    public static func resolveLabel(params: [String: String]) throws -> String {
        let raw = params["label"] ?? defaultLabel
        if raw.contains("/") || raw.contains("\\") || raw.contains("..") {
            throw RootstockError.invalidArgument("label must not contain path separators or '..'")
        }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-"))
        guard raw.unicodeScalars.allSatisfy({ allowed.contains($0) }), raw.contains(".") else {
            throw RootstockError.invalidArgument("label must be reverse-DNS form")
        }
        return raw
    }
}
