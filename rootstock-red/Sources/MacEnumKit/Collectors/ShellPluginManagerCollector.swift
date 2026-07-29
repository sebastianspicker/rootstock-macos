import Foundation
import RootstockCore

/// Shell plugin manager dual-use residual (Wave-15).
/// Safety and behavior: path inventory only; never installs oh-my-zsh plugins or rewrites shell init for persistence.
public struct ShellPluginManagerCollector: Collector {
    public static let id = "collect.shell_plugin_manager"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Shell plugin manager dual-use: path presence only - never installs oh-my-zsh plugins or rewrites shell init for persistence"]
        var a: [String] = []
        for path in [NSHomeDirectory() + "/.oh-my-zsh",
            NSHomeDirectory() + "/.oh-my-zsh/oh-my-zsh.sh",
            NSHomeDirectory() + "/.zprezto"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/.oh-my-zsh/custom/plugins",
            NSHomeDirectory() + "/.zsh/plugins",
            NSHomeDirectory() + "/.config/fish/conf.d"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/.zshrc",
            NSHomeDirectory() + "/.zprofile",
            NSHomeDirectory() + "/.bashrc"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.shellPluginManager = ShellPluginManagerState(
            omzPaths: a, pluginDirPaths: b, shellInitPaths: c,
            shellPluginSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
