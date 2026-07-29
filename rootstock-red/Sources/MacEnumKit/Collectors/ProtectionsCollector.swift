import Foundation
import RootstockCore
import RootstockMacFacts

/// SIP / Gatekeeper / FileVault posture via allowlisted read-only status CLIs.
///
/// Status CLI output is parsed through `HostPostureProbes` (RootstockMacFacts).
/// Process launch still uses red `AllowlistedProbe` for timeout/OPSEC control.
public struct ProtectionsCollector: Collector {
    public static let id = "collect.protections"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        var notes: [String] = [
            "Probe method: AllowlistedProbe + HostPostureProbes parsers (csrutil/spctl/fdesetup)",
            "No arbitrary shell; short timeout; parse via RootstockMacFacts",
        ]

        let sip = Self.probeSIP(&notes)
        let gatekeeper = Self.probeGatekeeper(&notes)
        let fileVault = Self.probeFileVault(&notes)

        var state = CollectedState()
        state.protections = ProtectionsState(
            sipEnabled: sip,
            gatekeeperEnabled: gatekeeper,
            fileVaultOn: fileVault,
            notes: notes
        )
        let known = [sip, gatekeeper, fileVault].compactMap { $0 }.count
        state.collectorNotes[Self.id] =
            "allowlisted status probes (\(known)/3 parseable) via HostPostureProbes"
        return state
    }

    // MARK: - SIP

    private static func probeSIP(_ notes: inout [String]) -> Bool? {
        let result = AllowlistedProbe.run(.csrutilStatus)
        if let err = result.errorDescription {
            notes.append("SIP: probe failed - \(err)")
            return nil
        }
        if result.timedOut {
            notes.append("SIP: csrutil timed out")
            return nil
        }
        notes.append(
            "SIP: csrutil exit=\(result.exitCode.map(String.init) ?? "?") raw=\(summarize(result.combinedOutput))"
        )
        if let value = HostPostureProbes.parseSIPOutput(result.combinedOutput) {
            return value
        }
        notes.append("SIP: output not parseable as enabled/disabled")
        return nil
    }

    // MARK: - Gatekeeper

    private static func probeGatekeeper(_ notes: inout [String]) -> Bool? {
        let result = AllowlistedProbe.run(.spctlStatus)
        if result.errorDescription == nil, !result.timedOut {
            notes.append(
                "Gatekeeper: spctl exit=\(result.exitCode.map(String.init) ?? "?") raw=\(summarize(result.combinedOutput))"
            )
            if let value = HostPostureProbes.parseGatekeeperOutput(result.combinedOutput) {
                return value
            }
            notes.append("Gatekeeper: spctl output not parseable; trying prefs heuristic")
        } else if let err = result.errorDescription {
            notes.append("Gatekeeper: spctl probe failed - \(err); trying prefs heuristic")
        } else if result.timedOut {
            notes.append("Gatekeeper: spctl timed out; trying prefs heuristic")
        }

        return gatekeeperFromPrefs(&notes)
    }

    /// Read-only prefs / path heuristic when spctl is unavailable.
    private static func gatekeeperFromPrefs(_ notes: inout [String]) -> Bool? {
        let fm = FileManager.default
        let globalPath = "/Library/Preferences/com.apple.security.plist"
        let userPath = NSHomeDirectory() + "/Library/Preferences/com.apple.security.plist"

        for path in [globalPath, userPath] where fm.fileExists(atPath: path) {
            notes.append("Gatekeeper: found \(path) (presence only; binary plist not fully parsed)")
        }

        notes.append("Gatekeeper: unknown without parseable spctl output")
        return nil
    }

    // MARK: - FileVault

    private static func probeFileVault(_ notes: inout [String]) -> Bool? {
        let result = AllowlistedProbe.run(.fdesetupStatus)
        if let err = result.errorDescription {
            notes.append("FileVault: probe failed - \(err)")
            return fileVaultPathHeuristic(&notes)
        }
        if result.timedOut {
            notes.append("FileVault: fdesetup timed out")
            return fileVaultPathHeuristic(&notes)
        }
        let text = result.combinedOutput
        notes.append(
            "FileVault: fdesetup exit=\(result.exitCode.map(String.init) ?? "?") raw=\(summarize(text))"
        )
        if let value = HostPostureProbes.parseFileVaultOutput(text) {
            return value
        }
        if let code = result.exitCode, code != 0 {
            notes.append("FileVault: non-zero exit (often requires admin); value unknown")
            return fileVaultPathHeuristic(&notes)
        }
        notes.append("FileVault: output not parseable")
        return fileVaultPathHeuristic(&notes)
    }

    /// Weak path heuristic only - does not prove FileVault on/off.
    private static func fileVaultPathHeuristic(_ notes: inout [String]) -> Bool? {
        let candidates = [
            HostPostureProbes.fdesetupPath,
            "/Library/Keychains/FileVaultMaster.keychain",
        ]
        let fm = FileManager.default
        for path in candidates {
            notes.append(
                "FileVault heuristic: \(path) exists=\(fm.fileExists(atPath: path))"
            )
        }
        notes.append("FileVault: unknown (no parseable fdesetup status)")
        return nil
    }

    private static func summarize(_ text: String, limit: Int = 160) -> String {
        let flat = text
            .replacingOccurrences(of: "\n", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if flat.count <= limit { return flat.isEmpty ? "<empty>" : flat }
        let idx = flat.index(flat.startIndex, offsetBy: limit)
        return String(flat[..<idx]) + "…"
    }
}
