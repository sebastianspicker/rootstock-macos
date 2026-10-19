import Foundation
import RootstockCore

/// Lab shell RC persistence marker - reversible line append under a configurable RC path.
///
/// Research basis: PersistentJXA / Empire shell-profile persistence technique catalog.
/// Safety and behavior: Swift lifecycle (plan/install/status/remove), consent, dry-run default,
/// path containment, no osascript runtime, explicit cleanup notes.
///
/// Marker is a harmless comment line only - never downloads payloads or starts C2.
public struct ShellRCLabAction: LabAction {
    public static let id = "lab.persist.shellrc"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let markerPrefix = "# rootstock-red-lab-shellrc-marker"
    public static let defaultMarker =
        "\(markerPrefix) id=com.rootstock.red.lab.shellrc # harmless; remove via lab remove"

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)

        let rcURL = try Self.resolveRCFile(params: request.parameters)
        let marker = request.parameters["marker"] ?? Self.defaultMarker

        switch request.operation {
        case .plan:
            return plan(rcURL: rcURL, marker: marker, dryRun: true)
        case .install:
            return try install(rcURL: rcURL, marker: marker, dryRun: context.dryRun)
        case .status:
            return try status(rcURL: rcURL, marker: marker)
        case .remove:
            return try remove(rcURL: rcURL, marker: marker, dryRun: context.dryRun)
        }
    }

    // MARK: - Operations

    private func plan(rcURL: URL, marker: String, dryRun: Bool) -> ActionResult {
        let steps = [
            "Target shell RC (user-controlled path only): \(rcURL.path)",
            "Append single harmless comment marker line if missing",
            "Marker: \(marker)",
            "Do not source remote URLs, curl pipes, or eval payloads",
            "Technique note: shell RC persistence is user-visible and high OPSEC cost on shared hosts",
        ]
        return ActionResult(
            actionId: Self.id,
            success: true,
            message: """
            Dry-run shell RC plan: would append marker to \(rcURL.path). \
            Harmless comment only - no payload, no network.
            """,
            dryRun: dryRun,
            plannedSteps: steps,
            cleanupNotes: [
                "Remove marker line via lab.persist.shellrc remove",
                "Inspect \(rcURL.path) for residual rootstock-red-lab markers",
            ],
            artifacts: [rcURL.path]
        )
    }

    private func install(rcURL: URL, marker: String, dryRun: Bool) throws -> ActionResult {
        let steps = [
            "Ensure parent directory exists for \(rcURL.path)",
            "Append marker if not already present",
            "Leave all other RC content untouched",
        ]
        let cleanup = [
            "Run remove operation or delete the line starting with \(Self.markerPrefix)",
            "Verify no residual \(Self.markerPrefix) in \(rcURL.path)",
        ]

        if dryRun {
            return installDryRunResult(rcURL: rcURL, steps: steps, cleanup: cleanup)
        }

        try LabMarkerLifecycle.assertNoUnsafeSymlinks(to: rcURL)
        let fm = FileManager.default
        let parent = rcURL.deletingLastPathComponent()
        try fm.createDirectory(at: parent, withIntermediateDirectories: true)

        var body = ""
        if fm.fileExists(atPath: rcURL.path) {
            body = try String(contentsOf: rcURL, encoding: .utf8)
        }
        if Self.hasMarkerLine(body) {
            return installAlreadyPresentResult(rcURL: rcURL, steps: steps, cleanup: cleanup)
        }
        if !body.isEmpty && !body.hasSuffix("\n") {
            body += "\n"
        }
        body += marker + "\n"
        try body.write(to: rcURL, atomically: true, encoding: .utf8)

        return installSuccessResult(rcURL: rcURL, steps: steps, cleanup: cleanup)
    }

    private func installDryRunResult(rcURL: URL, steps: [String], cleanup: [String]) -> ActionResult {
        ActionResult(actionId: Self.id, success: true, message: "Dry-run: would append shell RC marker to \(rcURL.path)", dryRun: true, plannedSteps: steps, cleanupNotes: cleanup, artifacts: [rcURL.path])
    }

    private func installAlreadyPresentResult(rcURL: URL, steps: [String], cleanup: [String]) -> ActionResult {
        ActionResult(actionId: Self.id, success: true, message: "Shell RC marker already present at \(rcURL.path)", dryRun: false, plannedSteps: steps + ["Skipped append - marker already present"], cleanupNotes: cleanup, artifacts: [rcURL.path])
    }

    private func installSuccessResult(rcURL: URL, steps: [String], cleanup: [String]) -> ActionResult {
        ActionResult(actionId: Self.id, success: true, message: "Installed shell RC lab marker at \(rcURL.path) (comment line only)", dryRun: false, plannedSteps: steps, cleanupNotes: cleanup, artifacts: [rcURL.path])
    }

    private func status(rcURL: URL, marker: String) throws -> ActionResult {
        try LabMarkerLifecycle.assertNoUnsafeSymlinks(to: rcURL)
        let fm = FileManager.default
        let exists = fm.fileExists(atPath: rcURL.path)
        var present = false
        if exists {
            let body = try String(contentsOf: rcURL, encoding: .utf8)
            present = Self.hasMarkerLine(body)
        }
        return ActionResult(
            actionId: Self.id,
            success: true,
            message: present
                ? "Shell RC marker present at \(rcURL.path)"
                : "Shell RC marker absent at \(rcURL.path) (fileExists=\(exists))",
            dryRun: false,
            plannedSteps: [
                "Read \(rcURL.path)",
                "Search for \(Self.markerPrefix): \(present)",
            ],
            cleanupNotes: present
                ? ["Remove marker via remove operation"]
                : ["No marker artifact"],
            artifacts: exists ? [rcURL.path] : []
        )
    }

    private func remove(rcURL: URL, marker: String, dryRun: Bool) throws -> ActionResult {
        let steps = [
            "Read \(rcURL.path) if present",
            "Drop lines starting with \(Self.markerPrefix)",
            "Rewrite file or leave absent files untouched",
        ]
        try LabMarkerLifecycle.assertNoUnsafeSymlinks(to: rcURL)
        let fm = FileManager.default
        let exists = fm.fileExists(atPath: rcURL.path)

        if dryRun {
            return ActionResult(
                actionId: Self.id,
                success: true,
                message: "Dry-run: would remove shell RC marker from \(rcURL.path) (exists=\(exists))",
                dryRun: true,
                plannedSteps: steps,
                cleanupNotes: ["Confirm no residual \(Self.markerPrefix)"],
                artifacts: exists ? [rcURL.path] : []
            )
        }

        guard exists else {
            return ActionResult(
                actionId: Self.id,
                success: true,
                message: "Shell RC file absent at \(rcURL.path) - nothing to remove",
                dryRun: false,
                plannedSteps: steps,
                cleanupNotes: ["No file artifact"],
                artifacts: []
            )
        }

        let body = try String(contentsOf: rcURL, encoding: .utf8)
        let filtered = body
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !Self.isMarkerLine($0) }
            .map(String.init)
            .joined(separator: "\n")
        try filtered.write(to: rcURL, atomically: true, encoding: .utf8)

        return ActionResult(
            actionId: Self.id,
            success: true,
            message: "Removed shell RC lab marker lines from \(rcURL.path)",
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: ["Confirm no residual \(Self.markerPrefix)"],
            artifacts: [rcURL.path]
        )
    }

    // MARK: - Paths

    /// Resolve RC path; defaults under ~/Library/RootstockLab for safety (not ~/.zshrc).
    public static func resolveRCFile(params: [String: String]) throws -> URL {
        if let path = params["rcFile"], !path.isEmpty {
            let url = URL(fileURLWithPath: path).standardizedFileURL
            try assertSafeRCPath(url)
            return url
        }
        let url: URL
        if let labRoot = params["labRoot"], !labRoot.isEmpty {
            let root = URL(fileURLWithPath: labRoot, isDirectory: true).standardizedFileURL
            url = root.appendingPathComponent("dotfiles").appendingPathComponent(".zshrc_lab")
        } else {
            // Safe default: never touch the user's real ~/.zshrc unless explicitly passed.
            url = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/RootstockLab/dotfiles/.zshrc_lab")
                .standardizedFileURL
        }
        try assertSafeRCPath(url)
        return url
    }

    /// A lab marker is a whole line that starts with the marker prefix; a mention elsewhere does not count.
    static func isMarkerLine<S: StringProtocol>(_ line: S) -> Bool {
        line.hasPrefix(markerPrefix)
    }

    static func hasMarkerLine(_ body: String) -> Bool {
        body.split(whereSeparator: \.isNewline).contains { isMarkerLine($0) }
    }

    /// Accept an rcFile only when the lab owns it: the file is absent, empty, or already has a
    /// lab marker line. Real shell startup files must already carry the marker even when absent.
    public static func assertSafeRCPath(_ url: URL) throws {
        let path = url.standardizedFileURL.path
        if path.contains("\0") {
            throw RootstockError.invalidArgument("rcFile path must not contain NUL")
        }
        guard !path.isEmpty else {
            throw RootstockError.invalidArgument("rcFile must not be empty")
        }
        let protectedNames: Set<String> = [
            ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".profile",
        ]
        let fileExists = FileManager.default.fileExists(atPath: path)
        let existing = try? String(contentsOf: url.standardizedFileURL, encoding: .utf8)
        if let existing, hasMarkerLine(existing) { return }
        if protectedNames.contains(url.lastPathComponent) {
            throw RootstockError.invalidArgument(
                "rcFile \(path) is a real shell startup file without a lab marker; use a dedicated lab file under ~/Library/RootstockLab"
            )
        }
        guard fileExists else { return }
        guard existing?.isEmpty == true else {
            throw RootstockError.invalidArgument(
                "rcFile \(path) already exists without a lab marker; refusing to modify a file the lab does not own"
            )
        }
    }
}
