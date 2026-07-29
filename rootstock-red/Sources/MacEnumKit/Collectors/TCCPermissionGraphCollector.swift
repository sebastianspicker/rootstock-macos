import Foundation
import RootstockCore

/// Multi-domain TCC permission graph (non-prompting, assess-safe).
///
/// Research basis: SwiftBelt path probes; PEASS TCC themes; Screen/AX/Automation research.
/// Safety and behavior: domain-level signal graph into `TCCState.domainSignals` + notes;
/// never dumps TCC.db rows; never forces permission dialogs; compounds domains for depth.
public struct TCCPermissionGraphCollector: Collector {
    public static let id = "collect.tcc_permission_graph"
    public static let cost: CollectorCost = .medium

    private struct GraphEvidence {
        let domainSignals: [String]
        let screenRecordingSignal: String
        let accessibilitySignal: String
        let systemTCCReadable: Bool
        let fullDiskAccessSignal: String
    }

    private struct ScreenCaptureEvidence {
        let signal: String
        let binaryPresent: Bool
    }

    private struct DomainSignalInputs {
        let screen: String
        let accessibility: String
        let automationPresent: Bool
        let avFoundationPresent: Bool
        let diskAccess: String
        let listableFolders: [String]
    }

    private static let systemTCCPath = "/Library/Application Support/com.apple.TCC/TCC.db"

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser
        var notes: [String] = [
            "TCC permission graph: non-prompting domain heuristics only",
        ]
        let evidence = collectDomainEvidence(fm: fm, home: home, notes: &notes)
        return collectedState(evidence: evidence, notes: notes)
    }

    private func collectDomainEvidence(
        fm: FileManager,
        home: URL,
        notes: inout [String]
    ) -> GraphEvidence {
        let screen = screenCaptureEvidence(fm: fm, home: home)
        let accessibility = accessibilitySignal(fm: fm, home: home)
        let automationPresent = fm.fileExists(atPath: "/usr/bin/osascript")
        let avFoundationPresent = fm.fileExists(atPath: "/System/Library/Frameworks/AVFoundation.framework")
        let diskAccess = fullDiskAccessEvidence(fm: fm, home: home)
        let listableFolders = listableFolders(fm: fm, home: home)

        recordScreenCapture(screen, notes: &notes)
        recordAccessibility(accessibility, notes: &notes)
        recordAutomation(automationPresent, notes: &notes)
        recordCameraMic(avFoundationPresent, notes: &notes)
        recordFullDiskAccess(diskAccess.signal, notes: &notes)
        recordFilesAndFolders(listableFolders, notes: &notes)

        let signalInputs = DomainSignalInputs(
            screen: screen.signal,
            accessibility: accessibility,
            automationPresent: automationPresent,
            avFoundationPresent: avFoundationPresent,
            diskAccess: diskAccess.signal,
            listableFolders: listableFolders
        )
        return GraphEvidence(
            domainSignals: domainSignals(signalInputs),
            screenRecordingSignal: screen.signal,
            accessibilitySignal: accessibility,
            systemTCCReadable: diskAccess.systemTCCReadable,
            fullDiskAccessSignal: diskAccess.signal
        )
    }

    private func screenCaptureEvidence(fm: FileManager, home: URL) -> ScreenCaptureEvidence {
        let binaryPresent = fm.fileExists(atPath: "/usr/sbin/screencapture")
        guard binaryPresent else {
            return ScreenCaptureEvidence(signal: "tool_absent", binaryPresent: false)
        }
        let foldersListable = ["Pictures", "Desktop"].contains {
            (try? fm.contentsOfDirectory(atPath: home.appendingPathComponent($0).path)) != nil
        }
        let signal = foldersListable ? "tool_present_folders_listable" : "tool_present"
        return ScreenCaptureEvidence(signal: signal, binaryPresent: true)
    }

    private func accessibilitySignal(fm: FileManager, home: URL) -> String {
        let candidates = [
            home.appendingPathComponent("Library/Application Support/com.apple.TCC").path,
            "/Library/Application Support/com.apple.TCC",
        ]
        return candidates.contains { fm.fileExists(atPath: $0) }
            ? "tcc_support_paths_present"
            : "unknown"
    }

    private func fullDiskAccessEvidence(fm: FileManager, home: URL) -> (signal: String, systemTCCReadable: Bool) {
        let systemTCCReadable = fm.isReadableFile(atPath: Self.systemTCCPath)
        let safariHistory = home.appendingPathComponent("Library/Safari/History.db").path
        if systemTCCReadable { return ("likely", true) }
        if fm.isReadableFile(atPath: safariHistory) { return ("possible", false) }
        return ("not_indicated", false)
    }

    private func listableFolders(fm: FileManager, home: URL) -> [String] {
        ["Desktop", "Documents", "Downloads"].filter {
            (try? fm.contentsOfDirectory(atPath: home.appendingPathComponent($0).path)) != nil
        }
    }

    private func domainSignals(_ inputs: DomainSignalInputs) -> [String] {
        [
            "ScreenCapture=\(inputs.screen)",
            "Accessibility=\(inputs.accessibility)",
            "Automation=\(inputs.automationPresent ? "osascript_present" : "osascript_absent")",
            "CameraMic=\(inputs.avFoundationPresent ? "avfoundation_present" : "unknown")",
            "FullDiskAccess=\(inputs.diskAccess)",
            "FilesAndFolders=\(inputs.listableFolders.isEmpty ? "none_listable" : inputs.listableFolders.joined(separator: "+"))",
        ]
    }

    private func recordScreenCapture(_ evidence: ScreenCaptureEvidence, notes: inout [String]) {
        notes.append("ScreenCapture signal=\(evidence.signal) bin=\(evidence.binaryPresent)")
    }

    private func recordAccessibility(_ signal: String, notes: inout [String]) {
        notes.append("Accessibility signal=\(signal)")
    }

    private func recordAutomation(_ present: Bool, notes: inout [String]) {
        notes.append("Automation osascript present=\(present)")
    }

    private func recordCameraMic(_ present: Bool, notes: inout [String]) {
        notes.append("Camera/Mic: AVFoundation present=\(present) (no device open)")
    }

    private func recordFullDiskAccess(_ signal: String, notes: inout [String]) {
        notes.append("FDA graph signal=\(signal)")
    }

    private func recordFilesAndFolders(_ folders: [String], notes: inout [String]) {
        notes.append("Files-and-Folders listable: \(folders.joined(separator: ",").ifEmpty("none"))")
    }

    private func collectedState(evidence: GraphEvidence, notes: [String]) -> CollectedState {
        let screenNote = "screen_recording=\(evidence.screenRecordingSignal)|accessibility=\(evidence.accessibilitySignal)"
        let fullDiskAccessLikely: Bool? = evidence.systemTCCReadable
            ? true
            : (evidence.fullDiskAccessSignal == "not_indicated" ? false : nil)
        var state = CollectedState()
        state.tcc = TCCState(
            fullDiskAccessLikely: fullDiskAccessLikely,
            notes: notes + ["screen_ax_compound=\(screenNote)"],
            probeMethod: "tcc_permission_graph_domains_v1",
            domainSignals: evidence.domainSignals
        )
        state.collectorNotes[Self.id] = evidence.domainSignals.joined(separator: ";")
        state.collectorNotes["tcc.screen_accessibility"] = screenNote
        return state
    }
}

private extension String {
    func ifEmpty(_ fallback: String) -> String {
        isEmpty ? fallback : self
    }
}
