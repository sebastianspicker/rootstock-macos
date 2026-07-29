import Foundation
import RootstockCore

/// Path-to-impact: modern login-item / SMAppService / BTM honesty for persistence validation.
///
/// Research basis: PersistentJXA login-item techniques; Apple SMAppService era persistence.
/// Safety and behavior: never claims silent persistence - BTM/user-visible registration is first-class OPSEC;
/// distinct from user LaunchAgents vector by focusing on BTM store + login-item paths.
public struct SMAppLoginItemHonestyVector: Check {
    public static let id = "rootstock.vector.persist.smapp_loginitem_honesty"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard Self.hasLoginItemSurface(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }


    private static func loginPaths(_ state: CollectedState) -> [String] {
        state.loginItemPaths.isEmpty ? (state.loginItems?.loginItemPaths ?? []) : state.loginItemPaths
    }

    private static func btmPresent(_ state: CollectedState) -> Bool {
        state.loginItems?.btmStorePresent == true || state.btmStorePresent == true
    }

    private static func hasLoginItemSurface(_ state: CollectedState) -> Bool {
        let paths = loginPaths(state)
        let legacy = paths.contains { $0.localizedCaseInsensitiveContains("loginitem") || $0.localizedCaseInsensitiveContains("backgrounditems") || $0.localizedCaseInsensitiveContains("ServiceManagement") || $0.localizedCaseInsensitiveContains("LoginItems") }
        return btmPresent(state) || !paths.isEmpty || (state.loginItems != nil && (!state.launchAgents.isEmpty || legacy))
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let login = state.loginItems, paths = Self.loginPaths(state), agents = state.launchAgents
        var evidence: [Evidence] = [Evidence(type: "btm", detail: "btmStorePresent=\(Self.btmPresent(state)) loginItemPaths=\(paths.count)")]
        if let dir = login?.btmDirectoryPath { evidence.append(Evidence(type: "btm_dir", path: dir, detail: "sizeBytes=\(login?.btmDirectorySizeBytes.map(String.init) ?? "unknown")")) }
        if let bg = login?.backgroundItemsBtmPath { evidence.append(Evidence(type: "backgrounditems", path: bg, detail: "BackgroundItems path present")) }
        for path in paths.prefix(20) { evidence.append(Evidence(type: "login_item_path", path: path, detail: "path present")) }
        for note in (login?.notes ?? []).prefix(10) { evidence.append(Evidence(type: "note", detail: note)) }
        if !agents.isEmpty { evidence.append(Evidence(type: "compound_launchagents", detail: "userLaunchAgents=\(agents.count) - new agents may surface in Login Items UI")) }
        evidence.append(Evidence(type: "smapp_honesty", detail: "SMAppService / Login Items on Ventura+ are user-visible via BTM; " + "silent persistence claims are false on modern macOS"))
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let btm = btmPresent(state), agents = state.launchAgents, paths = loginPaths(state)
        let title = btm && !agents.isEmpty ? "Login-item / SMAppService honesty: BTM present with user LaunchAgents (\(agents.count))" : (btm ? "Login-item / SMAppService honesty: BTM store evidence present" : "Login-item path surface without confirmed BTM store (\(paths.count) paths)")
        return Finding(id: Self.id, title: title, severity: !agents.isEmpty && btm ? .medium : .low, category: .persist, resolution: .init(evidence: evidence, attackTechniques: ["T1547.015", "T1543.001", "T1547"], remediation: ["Review System Settings → General → Login Items & Extensions for unexpected items", "Prefer SMAppService-registered apps over ad-hoc LaunchAgent drops in authorized labs", "OPSEC: treat login-item registration as high user-visibility / high OPSEC cost", "Do not claim silent persistence on modern macOS - BTM may notify the user"], falsePositiveNotes: "BTM store presence is normal after apps register background tasks. " + "Opaque BTM format is not fully decoded - path/size evidence only."), runtime: .init(confidence: btm ? .high : .low, dryRunSafe: true, opsecScore: 70, esfExpected: ["OPEN", "USER_PROMPT"], osRange: ">=13.0"))
    }
}
