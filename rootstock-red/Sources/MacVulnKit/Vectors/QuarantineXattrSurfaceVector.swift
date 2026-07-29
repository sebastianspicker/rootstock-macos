import Darwin
import Foundation
import RootstockCore

/// Path-to-impact: download-origin files still carrying `com.apple.quarantine` xattr.
///
/// Research basis: Gatekeeper / download-origin trust checks; PEASS quarantine inventory themes.
/// Safety and behavior: metadata-only xattr probes (never strip quarantine); compounds with Gatekeeper off;
/// collectorNotes force for tests.
public struct QuarantineXattrSurfaceVector: Check {
    public static let id = "rootstock.vector.codesign.quarantine_xattr_surface"
    public static let cost: CollectorCost = .low

    private static let quarantineAttr = "com.apple.quarantine"
    /// Max files to probe across all dirs (low-cost assess).
    private static let maxProbeFiles = 60
    /// Max quarantine hits to surface as evidence.
    private static let maxSampleHits = 25
    private static let maxPerDir = 25

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let inventory = Self.quarantineInventory(state)
        let forced = state.collectorNotes["codesign.quarantine_hits"] != nil
        guard !inventory.hits.isEmpty || forced else { return [] }
        let gkOff = state.protections?.gatekeeperEnabled == false
        return [Self.finding(state: state, inventory: inventory, forced: forced, gkOff: gkOff)]
    }

    private static func quarantineInventory(_ state: CollectedState) -> (hits: [String], probed: Int) {
        var hits = forcedHits(state)
        let home = FileManager.default.homeDirectoryForCurrentUser
        let directories = [home.appendingPathComponent("Downloads").path, home.appendingPathComponent("Desktop").path, NSTemporaryDirectory(), "/tmp"]
        var probed = 0
        for directory in uniquePaths(directories) {
            guard probed < maxProbeFiles else { break }
            let batch = scanDirectoryForQuarantine(directory, limit: min(maxPerDir, maxProbeFiles - probed))
            probed += batch.probed
            hits.append(contentsOf: batch.hits)
        }
        return (uniquePaths(hits), probed)
    }

    private static func forcedHits(_ state: CollectedState) -> [String] {
        guard let note = state.collectorNotes["codesign.quarantine_hits"] else { return [] }
        return note.split(separator: "|").map { String($0).trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    private static func finding(state: CollectedState, inventory: (hits: [String], probed: Int), forced: Bool, gkOff: Bool) -> Finding {
        let presentation = Self.presentation(hits: inventory.hits, gkOff: gkOff)
        return Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .codesign, resolution: .init(evidence: evidence(state: state, inventory: inventory, forced: forced, gkOff: gkOff), attackTechniques: ["T1553.001", "T1204.002", "T1036"], remediation: ["Keep Gatekeeper enabled; prefer Developer ID + notarized software distribution", "Educate users on unexpected Downloads/Desktop payloads still under quarantine", "Monitor unusual clear-of-quarantine activity via EDR (xattr -d storms)", "OPSEC: Rootstock Red never strips quarantine - assess is metadata-only"], falsePositiveNotes: "Quarantine tags on Downloads are normal after browser saves. Finding ranks download-origin surface and GK compound, not malware presence."), runtime: .init(confidence: inventory.hits.isEmpty ? .low : .medium, dryRunSafe: true, opsecScore: 18, esfExpected: ["OPEN"]))
    }

    private static func evidence(state: CollectedState, inventory: (hits: [String], probed: Int), forced: Bool, gkOff: Bool) -> [Evidence] {
        var evidence = [Evidence(type: "summary", detail: "quarantineHits=\(inventory.hits.count) probedFiles≈\(inventory.probed) gatekeeperEnabled=\((state.protections?.gatekeeperEnabled).rootstockDescribe) forced=\(forced) (xattr metadata only - never strip quarantine)")]
        if gkOff { evidence.append(Evidence(type: "gk_compound", detail: "Gatekeeper disabled compounds quarantine-origin download surface (T1553.001 / T1204.002 path-to-impact)")) }
        evidence += inventory.hits.prefix(maxSampleHits).map { Evidence(type: "quarantine_xattr", path: $0, detail: "com.apple.quarantine present (getxattr size≥0; content not parsed)") }
        evidence.append(Evidence(type: "opsec_honesty", detail: "Assess never clears quarantine (`xattr -d` / spctl --add) - metadata inventory only for authorized RT ranking"))
        return evidence
    }

    private static func presentation(hits: [String], gkOff: Bool) -> (severity: Severity, title: String) {
        if gkOff && !hits.isEmpty { return (.medium, "Quarantine xattr surface: download-origin hits with Gatekeeper off (\(hits.count))") }
        if !hits.isEmpty { return (.low, "Quarantine xattr surface: download-origin files still tagged (\(hits.count))") }
        return (.low, "Quarantine xattr surface: collector-forced inventory signals")
    }

    // MARK: - Probe helpers

    private static func scanDirectoryForQuarantine(
        _ dir: String,
        limit: Int
    ) -> (hits: [String], probed: Int) {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: dir, isDirectory: &isDir), isDir.boolValue else {
            return ([], 0)
        }
        guard let kids = try? fm.contentsOfDirectory(atPath: dir) else { return ([], 0) }

        var hits: [String] = []
        var probed = 0
        for name in kids.prefix(limit * 2) {
            if probed >= limit { break }
            // Skip hidden noise and deep trees - shallow top-level only.
            if name.hasPrefix(".") { continue }
            let path = (dir as NSString).appendingPathComponent(name)
            var childDir: ObjCBool = false
            if fm.fileExists(atPath: path, isDirectory: &childDir), childDir.boolValue {
                continue
            }
            probed += 1
            if hasQuarantineXattr(path) {
                hits.append(path)
            }
        }
        return (hits, probed)
    }

    /// Metadata-only: attribute presence via getxattr size query (no value parse, no remove).
    private static func hasQuarantineXattr(_ path: String) -> Bool {
        let size = getxattr(path, quarantineAttr, nil, 0, 0, 0)
        return size >= 0
    }

    private static func uniquePaths(_ paths: [String]) -> [String] {
        var seen = Set<String>()
        return paths.filter { seen.insert($0).inserted }
    }

}
