import Foundation
import RootstockCore

/// Path-to-impact: system LaunchDaemons / system LaunchAgents as persistence and privesc surface.
///
/// Research basis: PersistentJXA / PEASS system launchd inventory; Objective-See persistence taxonomy.
/// Safety and behavior: path-to-impact ranking (writable, unlabeled, compound weak SIP) vs pure inventory
/// (see also `SystemLaunchdInventoryCheck` for info-only listing).
public struct SystemLaunchDaemonSurfaceVector: Check {
    public static let id = "rootstock.vector.persist.system_launchdaemon_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let agents = state.systemLaunchAgents
        let daemons = state.launchDaemons
        let combined = agents + daemons
        guard !combined.isEmpty else { return [] }
        let surfaces = Self.surfaces(combined)
        let sipOff = state.protections?.sipEnabled == false
        let largeSurface = combined.count >= 3
        guard !surfaces.writable.isEmpty || largeSurface || !surfaces.unlabeled.isEmpty || sipOff else { return [] }
        return [Self.finding(agents: agents, daemons: daemons, combined: combined, surfaces: surfaces, sipOff: sipOff)]
    }

    private struct LaunchSurfaces { let writable: [LaunchAgentEntry]; let unlabeled: [LaunchAgentEntry] }

    private static func surfaces(_ entries: [LaunchAgentEntry]) -> LaunchSurfaces {
        let writable = entries.filter { entry in
            let parent = URL(fileURLWithPath: entry.path).deletingLastPathComponent().path
            return FileManager.default.isWritableFile(atPath: entry.path) || FileManager.default.isWritableFile(atPath: parent)
        }
        let unlabeled = entries.filter { $0.label == nil || $0.label?.isEmpty == true }
        return LaunchSurfaces(writable: writable, unlabeled: unlabeled)
    }

    private static func finding(agents: [LaunchAgentEntry], daemons: [LaunchAgentEntry], combined: [LaunchAgentEntry], surfaces: LaunchSurfaces, sipOff: Bool) -> Finding {
        let presentation = Self.presentation(combined: combined, writable: surfaces.writable, sipOff: sipOff)
        return Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .persist, resolution: .init(evidence: evidence(agents: agents, daemons: daemons, combined: combined, surfaces: surfaces, sipOff: sipOff), attackTechniques: ["T1543.001", "T1543.004", "T1068", "T1053.004"], remediation: ["Audit /Library/LaunchDaemons and /Library/LaunchAgents for unexpected Labels", "Enforce root:wheel ownership and non-user-writable modes on system launchd plists", "Re-enable SIP if disabled; manage daemons via signed packages / MDM", "OPSEC: reading system launchd dirs is low noise; writing them requires root and is lab-gated"], falsePositiveNotes: "Vendor system daemons are normal. Writable hits under temp/lab trees may be synthetic. Inventory-only hosts with locked plists may still fire at medium when surface is large."), runtime: .init(confidence: surfaces.writable.isEmpty ? .medium : .high, dryRunSafe: true, opsecScore: 24, esfExpected: ["OPEN", "WRITE"]))
    }

    private static func evidence(agents: [LaunchAgentEntry], daemons: [LaunchAgentEntry], combined: [LaunchAgentEntry], surfaces: LaunchSurfaces, sipOff: Bool) -> [Evidence] {
        var evidence = [Evidence(type: "summary", detail: "systemLaunchAgents=\(agents.count) launchDaemons=\(daemons.count) writable=\(surfaces.writable.count) unlabeled=\(surfaces.unlabeled.count) sipOff=\(sipOff)")]
        evidence += surfaces.writable.prefix(20).map { Evidence(type: "writable_system_launchd", path: $0.path, detail: "label=\($0.label ?? "unlabeled") program=\($0.programArguments.prefix(2).joined(separator: " "))") }
        let sample = surfaces.writable.isEmpty ? combined : daemons
        evidence += sample.filter { entry in !surfaces.writable.contains(where: { $0.path == entry.path }) }.prefix(20).map { Evidence(type: "system_launchd", path: $0.path, detail: "label=\($0.label ?? "unlabeled")") }
        if sipOff { evidence.append(Evidence(type: "sip_compound", detail: "SIP disabled compounds system launchd abuse into higher impact")) }
        evidence.append(Evidence(type: "btm_honesty", detail: "System LaunchDaemons are not user BTM login items; still monitor launchd loads via ESF"))
        return evidence
    }

    private static func presentation(combined: [LaunchAgentEntry], writable: [LaunchAgentEntry], sipOff: Bool) -> (severity: Severity, title: String) {
        if !writable.isEmpty && sipOff { return (.critical, "System launchd vector: writable daemons/agents with SIP off (\(writable.count))") }
        if !writable.isEmpty { return (.high, "System launchd vector: user-writable system agents/daemons (\(writable.count))") }
        if sipOff { return (.medium, "System launchd surface (\(combined.count)) with SIP disabled") }
        return (.medium, "System LaunchDaemon / system LaunchAgent attack surface (\(combined.count))")
    }
}
