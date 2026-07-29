import Foundation
import RootstockCore

private struct LaunchAgentInstallRequest {
    let plistURL: URL
    let label: String
    let program: String
    let markerArg: String
    let directory: URL
    let dryRun: Bool
}

/// Lab LaunchAgent lifecycle: install / status / remove of a harmless marker plist.
///
/// Writes only under a configurable directory (default `~/Library/LaunchAgents`).
/// Program is `/usr/bin/true` (no payload). Does not call `launchctl`.
///
/// **BTM honesty:** macOS Background Task Management may still surface residual
/// entries after plist deletion until the user clears Login Items / Background
/// Items in System Settings, or until BTM reaps the registration.
public struct LaunchAgentLabAction: LabAction {
    public static let id = "lab.persist.launchagent"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let defaultLabelPrefix = "com.rootstock.red.lab"
    public static let btmCleanupNote = """
    BTM residual risk: deleting the plist does not guarantee removal from Background \
    Task Management / Login Items UI. Check System Settings → General → Login Items \
    & Extensions (or Login Items) and remove any com.rootstock.red.lab.* entries manually. \
    launchctl unload was not used; a reboot or user approval UI may still reference \
    the former Label until BTM refreshes.
    """

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)

        let params = request.parameters
        let directory = Self.resolveDirectory(params: params)
        let label = try Self.resolveLabel(params: params)
        let plistURL = try Self.resolvePlistURL(directory: directory, label: label)
        // Hard allowlist: only /usr/bin/true as program (no path injection via params).
        let program = "/usr/bin/true"
        let markerArg = "rootstock-red-lab-marker"

        switch request.operation {
        case .plan, .install:
            return try installOrPlan(
                request: LaunchAgentInstallRequest(
                    plistURL: plistURL,
                    label: label,
                    program: program,
                    markerArg: markerArg,
                    directory: directory,
                    dryRun: context.dryRun || request.operation == .plan
                )
            )
        case .status:
            return status(plistURL: plistURL, label: label)
        case .remove:
            return try remove(
                plistURL: plistURL,
                label: label,
                dryRun: context.dryRun
            )
        }
    }

    // MARK: - Operations

    private func installOrPlan(request: LaunchAgentInstallRequest) throws -> ActionResult {
        let steps = [
            "Ensure directory exists: \(request.directory.path)",
            "Write LaunchAgent plist: \(request.plistURL.path)",
            "Label=\(request.label) ProgramArguments=[\(request.program), \(request.markerArg)] (harmless; no C2/keylog)",
            "Do NOT call launchctl bootstrap/load (FileManager-only; avoids shell)",
            "BTM may register this Label if the user or system loads it later - user-visible risk",
        ]
        let cleanup = [
            "Delete \(request.plistURL.path) via remove operation or FileManager",
            Self.btmCleanupNote,
            "Verify no residual com.rootstock.red.lab.* under LaunchAgents",
        ]
        if request.dryRun {
            return dryRunInstallResult(request: request, steps: steps, cleanup: cleanup)
        }

        try writePlist(for: request)
        return installedResult(request: request, steps: steps, cleanup: cleanup)
    }

    private func dryRunInstallResult(
        request: LaunchAgentInstallRequest,
        steps: [String],
        cleanup: [String]
    ) -> ActionResult {
        return ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Dry-run: would install harmless LaunchAgent \(request.label) at \(request.plistURL.path). \
            BTM user-visible risk: if loaded, macOS may show a background item for this Label; \
            removal of the plist may leave residual BTM UI until cleared.
            """,
            dryRun: true,
            plannedSteps: steps,
            cleanupNotes: cleanup,
            artifacts: [request.plistURL.path]
        )
    }

    private func writePlist(for request: LaunchAgentInstallRequest) throws {
        try FileManager.default.createDirectory(at: request.directory, withIntermediateDirectories: true)
        let plistData = try Self.plistXML(
            label: request.label,
            program: request.program,
            markerArg: request.markerArg
        )
        try plistData.write(to: request.plistURL, options: .atomic)
    }

    private func installedResult(
        request: LaunchAgentInstallRequest,
        steps: [String],
        cleanup: [String]
    ) -> ActionResult {
        ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Installed lab LaunchAgent \(request.label) at \(request.plistURL.path) \
            (Program=\(request.program); harmless marker only). \
            BTM user-visible risk: if this agent is loaded, System Settings may list it; \
            delete the plist to reverse file-level persistence - BTM residual may remain.
            """,
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: cleanup,
            artifacts: [request.plistURL.path]
        )
    }

    private func status(plistURL: URL, label: String) -> ActionResult {
        let exists = FileManager.default.fileExists(atPath: plistURL.path)
        let steps = [
            "Check plist exists at \(plistURL.path): \(exists)",
            "Note: status does not query launchctl or BTM store (FileManager-only)",
        ]
        return ActionResult(
            actionId: Self.id,
            success: true,
            message: exists
                ? "LaunchAgent plist present for \(label) at \(plistURL.path). BTM may also list this Label if previously registered."
                : "LaunchAgent plist absent for \(label) at \(plistURL.path). BTM residual may still exist in System Settings if it was ever loaded.",
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: exists ? [Self.btmCleanupNote] : ["No file artifact; check BTM UI for residual Label \(label)"],
            artifacts: exists ? [plistURL.path] : []
        )
    }

    private func remove(plistURL: URL, label: String, dryRun: Bool) throws -> ActionResult {
        let steps = [
            "Delete plist if present: \(plistURL.path)",
            "Skip launchctl bootout/unload (prefer FileManager delete only)",
            "Document BTM residual risk for operator cleanup",
        ]
        let cleanup = [Self.btmCleanupNote]
        let exists = FileManager.default.fileExists(atPath: plistURL.path)

        if dryRun {
            return ActionResult(
                actionId: Self.id,
                success: true,
                message: """
                Dry-run: would delete LaunchAgent plist for \(label) at \(plistURL.path) \
                (exists=\(exists)). BTM may still show residual background item after file delete.
                """,
                dryRun: true,
                plannedSteps: steps,
                cleanupNotes: cleanup,
                artifacts: exists ? [plistURL.path] : []
            )
        }

        if exists {
            try FileManager.default.removeItem(at: plistURL)
        }

        return ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Removed LaunchAgent plist for \(label) at \(plistURL.path) \
            (wasPresent=\(exists)). BTM residual risk: System Settings may still list \
            \(label) until the user removes it or BTM refreshes - unload via launchctl was not performed.
            """,
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: cleanup,
            artifacts: exists ? [plistURL.path] : []
        )
    }

    // MARK: - Helpers

    public static func resolveDirectory(params: [String: String]) -> URL {
        if let directory = params["directory"], !directory.isEmpty {
            return URL(fileURLWithPath: directory, isDirectory: true).standardizedFileURL
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents", isDirectory: true)
            .standardizedFileURL
    }

    /// Reverse-DNS LaunchAgent label only - rejects path separators and `..`.
    public static func resolveLabel(params: [String: String]) throws -> String {
        if let label = params["label"], !label.isEmpty {
            return try sanitizeLabel(label)
        }
        let suffix = try sanitizeLabelComponent(params["suffix"] ?? "marker")
        return "\(defaultLabelPrefix).\(suffix)"
    }

    /// Build plist URL and assert it remains strictly under `directory`.
    public static func resolvePlistURL(directory: URL, label: String) throws -> URL {
        let safeLabel = try sanitizeLabel(label)
        let dir = directory.standardizedFileURL
        let plist = dir
            .appendingPathComponent("\(safeLabel).plist", isDirectory: false)
            .standardizedFileURL
        try assertPath(plist, isContainedIn: dir)
        return plist
    }

    /// Allow reverse-DNS labels: `com.rootstock.red.lab.foo` style only.
    public static func sanitizeLabel(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw RootstockError.invalidArgument("label must not be empty")
        }
        try rejectPathSyntax(in: trimmed)
        try validateLabelCharacters(in: trimmed)
        try validateLabelDots(in: trimmed)
        try validateReverseDNSForm(in: trimmed)
        return trimmed
    }

    private static func rejectPathSyntax(in label: String) throws {
        guard !label.contains("/"), !label.contains("\\"), !label.contains("..") else {
            throw RootstockError.invalidArgument(
                "label must be reverse-DNS only (no path separators or '..')"
            )
        }
    }

    private static func validateLabelCharacters(in label: String) throws {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-"))
        guard label.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw RootstockError.invalidArgument(
                "label may only contain letters, digits, '.', and '-'"
            )
        }
    }

    private static func validateLabelDots(in label: String) throws {
        guard !label.hasPrefix("."), !label.hasSuffix(".") else {
            throw RootstockError.invalidArgument("label has invalid leading/trailing or double dots")
        }
    }

    private static func validateReverseDNSForm(in label: String) throws {
        guard label.contains(".") else {
            throw RootstockError.invalidArgument(
                "label must be reverse-DNS form (e.g. com.rootstock.red.lab.test)"
            )
        }
    }

    private static func sanitizeLabelComponent(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains("/") || trimmed.contains("\\") || trimmed.contains("..") {
            throw RootstockError.invalidArgument("label suffix must not contain path separators or '..'")
        }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-"))
        let cleaned = String(trimmed.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" })
        guard !cleaned.isEmpty, cleaned != "." && cleaned != ".." else {
            throw RootstockError.invalidArgument("invalid label suffix")
        }
        return cleaned
    }

    /// Ensures `candidate` resolves to a file path strictly inside `directory`.
    public static func assertPath(_ candidate: URL, isContainedIn directory: URL) throws {
        let base = directory.standardizedFileURL
        let file = candidate.standardizedFileURL
        let basePath = base.path
        let filePath = file.path
        let prefix = basePath.hasSuffix("/") ? basePath : basePath + "/"
        guard filePath.hasPrefix(prefix), file.deletingLastPathComponent().standardizedFileURL.path == basePath
            || filePath.hasPrefix(prefix)
        else {
            throw RootstockError.invalidArgument(
                "resolved path escapes lab directory: \(filePath) not under \(basePath)"
            )
        }
        // Reject exact directory equality (must be a file under base).
        guard filePath != basePath else {
            throw RootstockError.invalidArgument("resolved path must be a file under lab directory")
        }
        guard filePath.hasPrefix(prefix) else {
            throw RootstockError.invalidArgument(
                "resolved path escapes lab directory: \(filePath) not under \(basePath)"
            )
        }
    }

    /// Property-list XML for a harmless LaunchAgent (no shell, no network).
    public static func plistXML(label: String, program: String, markerArg: String) throws -> Data {
        let dict: [String: Any] = [
            "Label": label,
            "ProgramArguments": [program, markerArg],
            "RunAtLoad": false,
            "KeepAlive": false,
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: dict,
            format: .xml,
            options: 0
        )
        return data
    }
}
