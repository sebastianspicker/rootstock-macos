import Foundation
import RootstockCore

/// TCC / ESF visibility-depth posture (Wave-9).
///
/// Research basis: ESF/eslogger/Unified Logging operator visibility literature; TCC.db path research.
/// Safety and behavior: typed depth label (strong/partial/thin); never dumps TCC.db rows or live-subscribes ESF.
public struct TCCESFVisibilityDepthCollector: Collector {
    public static let id = "collect.tcc_esf_visibility_depth"
    public static let cost: CollectorCost = .low

    private static let tccDbCandidates: [String] = [
        NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db",
        "/Library/Application Support/com.apple.TCC/TCC.db",
        "/private/var/db/SystemPolicyConfiguration",
        NSHomeDirectory() + "/Library/Application Support/com.apple.TCC",
        "/Library/Application Support/com.apple.TCC",
    ]

    private static let visibilityTools: [String] = [
        "/usr/bin/eslogger",
        "/usr/bin/log",
        "/usr/bin/log stream",
        "/usr/bin/sqlite3",
        "/usr/bin/fs_usage",
        "/usr/sbin/system_profiler",
        "/System/Library/Frameworks/EndpointSecurity.framework",
        "/Library/Developer/CommandLineTools/usr/bin/eslogger",
    ]

    private static let privacyPrefs: [String] = [
        NSHomeDirectory() + "/Library/Preferences/com.apple.TCC.plist",
        "/Library/Preferences/com.apple.TCC.plist",
        "/Library/Preferences/com.apple.security.plist",
        NSHomeDirectory() + "/Library/Preferences/com.apple.Logging.plist",
        "/System/Library/LaunchDaemons/com.apple.syslogd.plist",
        "/etc/asl.conf",
        "/private/etc/asl.conf",
    ]

    private struct TCCEvidence {
        let paths: [String]
        let readableCount: Int
    }

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "TCC/ESF visibility depth: path/listability only - never dumps TCC.db rows, never live-subscribes ESF without ROE",
        ]

        let tcc = tccEvidence(fm, notes: &notes)
        let tools = visibilityToolPaths(fm, notes: &notes)
        let prefs = privacyPreferencePaths(fm, notes: &notes)
        let depth = visibilityDepth(tcc: tcc, tools: tools)
        let surface = hasVisibilitySurface(tcc: tcc.paths, tools: tools, prefs: prefs)

        var state = CollectedState()
        state.tccEsfVisibilityDepth = TCCESFVisibilityDepthState(
            tccDbPathHits: tcc.paths,
            visibilityToolPaths: tools,
            privacyPrefPaths: prefs,
            visibilityDepth: depth,
            visibilitySurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "tcc=\(tcc.paths.count) readableTCC=\(tcc.readableCount) tools=\(tools.count) "
            + "prefs=\(prefs.count) depth=\(depth) surface=\(surface)"
        return state
    }

    private func tccEvidence(_ fm: FileManager, notes: inout [String]) -> TCCEvidence {
        var paths: [String] = []
        var readableCount = 0

        for path in Self.tccDbCandidates where fm.fileExists(atPath: path) {
            paths.append(path)
            let readable = fm.isReadableFile(atPath: path)
            if readable { readableCount += 1 }
            notes.append("tcc_path: \(path) readable=\(readable)")
        }

        return TCCEvidence(paths: uniqueSorted(paths), readableCount: readableCount)
    }

    private func visibilityToolPaths(_ fm: FileManager, notes: inout [String]) -> [String] {
        let candidates = Self.visibilityTools.filter { !$0.contains(" ") }
        return existingPaths(candidates, fm: fm, prefix: "visibility_tool", notes: &notes)
    }

    private func privacyPreferencePaths(_ fm: FileManager, notes: inout [String]) -> [String] {
        existingPaths(Self.privacyPrefs, fm: fm, prefix: "privacy_pref", notes: &notes)
    }

    private func existingPaths(
        _ candidates: [String],
        fm: FileManager,
        prefix: String,
        notes: inout [String]
    ) -> [String] {
        var paths: [String] = []
        for path in candidates where fm.fileExists(atPath: path) {
            paths.append(path)
            notes.append("\(prefix): \(path)")
        }
        return uniqueSorted(paths)
    }

    private func visibilityDepth(tcc: TCCEvidence, tools: [String]) -> String {
        if tcc.readableCount > 0 && tools.count >= 2 { return "strong" }
        if !tcc.paths.isEmpty || tools.count >= 2 { return "partial" }
        return "thin"
    }

    private func hasVisibilitySurface(tcc: [String], tools: [String], prefs: [String]) -> Bool {
        !tcc.isEmpty || !tools.isEmpty || !prefs.isEmpty
    }

    private func uniqueSorted(_ paths: [String]) -> [String] {
        Array(Set(paths)).sorted()
    }
}
