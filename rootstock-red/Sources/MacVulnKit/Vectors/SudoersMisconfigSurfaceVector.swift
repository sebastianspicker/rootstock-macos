import Foundation
import RootstockCore

/// Path-to-impact: sudoers / sudoers.d misconfiguration surface (read-only assessment).
///
/// Research basis: PEASS sudo checks; public sudo Host_Alias / NOPASSWD misconfig themes (e.g. CVE-2025-32462 class *requires misconfig*).
/// Safety and behavior: never runs `sudo -l` storms or weaponized exploits; path readability + collector notes;
/// typed Finding with ATT&CK, remediation, FP honesty.
public struct SudoersMisconfigSurfaceVector: Check {
    public static let id = "rootstock.vector.privesc.sudoers_misconfig_surface"
    public static let cost: CollectorCost = .low

    private static let probePaths = [
        "/etc/sudoers",
        "/private/etc/sudoers",
        "/etc/sudoers.d",
        "/private/etc/sudoers.d",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var signals = collectorSignals(in: state)
        signals.merge(fileSystemSignals(using: FileManager.default))
        signals.recordDropInWritability(using: FileManager.default)
        guard signals.isPresent else { return [] }

        var evidence = signals.evidence
        evidence.append(contentsOf: dropInEvidence(for: signals.dropins))
        evidence.append(contentsOf: readableFileEvidence(for: signals.readableFiles))
        let outcome = severityAndTitle(for: signals, state: state)
        evidence.append(contentsOf: writableEvidence(for: signals.writablePaths))
        evidence.insert(summaryEvidence(for: signals, state: state), at: 0)
        return [makeFinding(outcome: outcome, signals: signals, evidence: evidence)]
    }

    private struct SudoersSignals {
        var evidence: [Evidence] = []
        var readableFiles: [String] = []
        var writablePaths: [String] = []
        var dropins: [String] = []
        var collectorNotePresent = false

        var isPresent: Bool {
            !readableFiles.isEmpty || !writablePaths.isEmpty || !dropins.isEmpty || collectorNotePresent
        }

        mutating func merge(_ other: SudoersSignals) {
            evidence.append(contentsOf: other.evidence)
            readableFiles.append(contentsOf: other.readableFiles)
            writablePaths.append(contentsOf: other.writablePaths)
            dropins.append(contentsOf: other.dropins)
            collectorNotePresent = collectorNotePresent || other.collectorNotePresent
        }

        mutating func recordDropInWritability(using fileManager: FileManager) {
            writablePaths.append(contentsOf: dropins.filter { fileManager.isWritableFile(atPath: $0) })
        }
    }

    private func collectorSignals(in state: CollectedState) -> SudoersSignals {
        guard let note = state.collectorNotes["privesc.sudoers_signals"] else { return SudoersSignals() }
        var signals = SudoersSignals(
            evidence: [Evidence(type: "collector_note", detail: note)],
            collectorNotePresent: true
        )
        for part in note.split(separator: "|") {
            recordCollectorSignal(String(part).trimmingCharacters(in: .whitespaces), into: &signals)
        }
        return signals
    }

    private func recordCollectorSignal(_ signal: String, into signals: inout SudoersSignals) {
        if signal.hasPrefix("readable:") {
            signals.readableFiles.append(String(signal.dropFirst("readable:".count)))
            return
        }
        if signal.hasPrefix("writable:") {
            signals.writablePaths.append(String(signal.dropFirst("writable:".count)))
            return
        }
        if signal.hasPrefix("nopasswd_hint:") {
            signals.evidence.append(
                Evidence(type: "nopasswd_hint", detail: String(signal.dropFirst("nopasswd_hint:".count)))
            )
        }
    }

    private func fileSystemSignals(using fileManager: FileManager) -> SudoersSignals {
        var signals = SudoersSignals()
        for path in Self.probePaths {
            var isDirectory: ObjCBool = false
            guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory) else { continue }
            if isDirectory.boolValue {
                recordDirectorySignal(path, using: fileManager, into: &signals)
            } else {
                recordFileSignal(path, using: fileManager, into: &signals)
            }
        }
        return signals
    }

    private func recordDirectorySignal(_ path: String, using fileManager: FileManager, into signals: inout SudoersSignals) {
        if fileManager.isReadableFile(atPath: path) {
            signals.evidence.append(Evidence(type: "sudoers_dir", path: path, detail: "readable=true"))
            let children = (try? fileManager.contentsOfDirectory(atPath: path)) ?? []
            signals.dropins.append(contentsOf: children.prefix(20).map { "\(path)/\($0)" })
        }
        if fileManager.isWritableFile(atPath: path) {
            signals.writablePaths.append(path)
        }
    }

    private func recordFileSignal(_ path: String, using fileManager: FileManager, into signals: inout SudoersSignals) {
        if fileManager.isReadableFile(atPath: path) {
            signals.readableFiles.append(path)
        }
        if fileManager.isWritableFile(atPath: path) {
            signals.writablePaths.append(path)
        }
    }

    private func dropInEvidence(for paths: [String]) -> [Evidence] {
        paths.prefix(15).map { Evidence(type: "sudoers_dropin", path: $0, detail: "drop-in present") }
    }

    private func readableFileEvidence(for paths: [String]) -> [Evidence] {
        paths.prefix(10).map {
            Evidence(type: "sudoers_file", path: $0, detail: "readable=true (content not parsed for secrets)")
        }
    }

    private func writableEvidence(for paths: [String]) -> [Evidence] {
        paths.prefix(10).map { Evidence(type: "writable_sudoers", path: $0, detail: "writable=true") }
    }

    private func severityAndTitle(for signals: SudoersSignals, state: CollectedState) -> (severity: Severity, title: String) {
        if !signals.writablePaths.isEmpty {
            return (.critical, "Sudoers surface: user-writable sudoers path (\(signals.writablePaths.count))")
        }
        if state.host?.isRoot == true || state.protections?.sipEnabled == false {
            return (.medium, "Sudoers surface readable under elevated/weak-SIP context")
        }
        if !signals.dropins.isEmpty || !signals.readableFiles.isEmpty {
            return (.low, "Sudoers configuration surface present (readable paths - no content exploit)")
        }
        return (.low, "Sudoers misconfig surface signals present")
    }

    private func summaryEvidence(for signals: SudoersSignals, state: CollectedState) -> Evidence {
        Evidence(
            type: "summary",
            detail: "readableFiles=\(signals.readableFiles.count) dropins=\(signals.dropins.count) "
                + "writable=\(signals.writablePaths.count) isRoot=\(state.host?.isRoot == true) "
                + "(assess only - no sudo -l storm, no CVE exploit delivery)"
        )
    }

    private func makeFinding(
        outcome: (severity: Severity, title: String),
        signals: SudoersSignals,
        evidence: [Evidence]
    ) -> Finding {
        Finding(
            id: Self.id,
            title: outcome.title,
            severity: outcome.severity,
            category: .misconfig,
            resolution: .init(
                evidence: evidence,
                attackTechniques: ["T1548.003", "T1548", "T1068"],
                remediation: [
                    "Ensure /etc/sudoers and /etc/sudoers.d are root:wheel and not user-writable",
                    "Audit NOPASSWD and Host_Alias rules via authorized configuration management",
                    "Prefer least-privilege group policies over broad admin sudo",
                    "OPSEC: Rootstock Red does not execute sudo exploits or dump sudo -l by default",
                ],
                falsePositiveNotes: "Readable sudoers is common on stock macOS; finding is surface + writability ranking, "
                    + "not proof of a live privilege-escalation CVE. Content is not fully parsed."
            ),
            runtime: .init(
                confidence: signals.writablePaths.isEmpty ? .low : .medium,
                dryRunSafe: true,
                opsecScore: 18,
                esfExpected: ["OPEN"]
            )
        )
    }
}
