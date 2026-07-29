import Foundation
import RootstockCore

/// Launch-constraint / library-validation injectability truth (path + codesign note heuristics).
///
/// Research basis: InjectCheck-style HR/LV flags; Apple launch-constraint documentation themes.
/// Safety and behavior: explicit constrained vs unconstrained-risk path sets; never claims process
/// injection success; feeds `LaunchConstraintInjectTruthVector`.
public struct LaunchConstraintCollector: Collector {
    public static let id = "collect.launch_constraints"
    public static let cost: CollectorCost = .medium

    /// Lightweight sample set: common high-value app locations (metadata only).
    private static let sampleRoots: [String] = [
        "/Applications",
        "/usr/local/bin",
        "/opt/homebrew/bin",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        var accumulator = CollectionAccumulator()
        for app in Self.sampleApps() {
            Self.process(app: app, accumulator: &accumulator)
        }
        for root in Self.sampleRoots {
            accumulator.notes.append("sample_root_exists=\(FileManager.default.fileExists(atPath: root)): \(root)")
        }
        return Self.state(from: accumulator)
    }


    private struct CollectionAccumulator {
        var notes = ["Launch-constraint honesty: path/codesign heuristics only - no runtime inject"]
        var constrained: [String] = []
        var unconstrainedRisk: [String] = []
        var injectHits: [InjectabilityHit] = []
        var codesignSamples: [CodesignSample] = []
    }

    private static func sampleApps() -> [URL] {
        let root = URL(fileURLWithPath: "/Applications", isDirectory: true)
        let contents = (try? FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )) ?? []
        return contents.filter { $0.pathExtension == "app" }.prefix(12).map { $0 }
    }

    private static func process(app: URL, accumulator: inout CollectionAccumulator) {
        let fm = FileManager.default
        let info = app.appendingPathComponent("Contents/Info.plist")
        guard fm.fileExists(atPath: info.path) else { return }
        let constraints = [app.appendingPathComponent("Contents/Library/LaunchConstraints"), app.appendingPathComponent("Contents/Resources/launchd-constraint.plist"), app.appendingPathComponent("Contents/CodeResources")]
        let artifacts = constraints.filter { fm.fileExists(atPath: $0.path) }
        accumulator.constrained.append(contentsOf: artifacts.map(\.path))
        accumulator.notes.append(contentsOf: artifacts.map { "constraint-ish artifact: \($0.path)" })
        let macOS = app.appendingPathComponent("Contents/MacOS", isDirectory: true)
        guard let first = try? fm.contentsOfDirectory(atPath: macOS.path).first else { return }
        let path = macOS.appendingPathComponent(first).path
        let sample = codesignProbe(path: path)
        accumulator.codesignSamples.append(sample)
        let flags = riskFlags(from: sample)
        if !flags.isEmpty {
            accumulator.injectHits.append(InjectabilityHit(path: path, hardenedRuntime: sample.hardenedRuntime, getTaskAllow: sample.getTaskAllow, disableLibraryValidation: sample.disableLibraryValidation, allowDyldEnvironmentVariables: sample.allowDyldEnvironmentVariables, allowUnsignedExecutableMemory: sample.allowUnsignedExecutableMemory, riskFlags: flags, notes: sample.notes))
            if artifacts.isEmpty {
                accumulator.unconstrainedRisk.append(path)
                accumulator.notes.append("risk without constraint artifact: \(path) flags=\(flags.joined(separator: ","))")
            }
        } else if !artifacts.isEmpty {
            accumulator.notes.append("constrained sample with no entitlement risk flags: \(path)")
        }
    }

    private static func state(from accumulator: CollectionAccumulator) -> CollectedState {
        var state = CollectedState()
        state.launchConstraints = LaunchConstraintState(constrainedPaths: Array(Set(accumulator.constrained)).sorted(), unconstrainedRiskPaths: Array(Set(accumulator.unconstrainedRisk)).sorted(), notes: accumulator.notes)
        if !accumulator.injectHits.isEmpty { state.injectabilityHits = accumulator.injectHits }
        if !accumulator.codesignSamples.isEmpty { state.codesignSamples = accumulator.codesignSamples }
        state.collectorNotes[Self.id] = "constrained=\(accumulator.constrained.count) unconstrainedRisk=\(accumulator.unconstrainedRisk.count) " + "injectSamples=\(accumulator.injectHits.count)"
        return state
    }

    /// Best-effort codesign display via Process (allowlisted security tooling).
    private static func codesignProbe(path: String) -> CodesignSample {
        var sample = CodesignSample(path: path, notes: ["launch_constraint_collector_probe"])
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        proc.arguments = ["-d", "--entitlements", ":-", path]
        let out = Pipe()
        let err = Pipe()
        proc.standardOutput = out
        proc.standardError = err
        do {
            try proc.run()
            proc.waitUntilExit()
        } catch {
            sample.notes.append("codesign spawn failed: \(error.localizedDescription)")
            return sample
        }
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        let outData = out.fileHandleForReading.readDataToEndOfFile()
        let text = String(data: errData + outData, encoding: .utf8) ?? ""
        sample.signed = proc.terminationStatus == 0 || text.contains("Authority=")
        if text.localizedCaseInsensitiveContains("flags=0x")
            || text.localizedCaseInsensitiveContains("runtime")
        {
            sample.hardenedRuntime =
                text.localizedCaseInsensitiveContains("runtime")
                || text.contains("flags=0x10000")
                || text.contains("flags=0x30000")
        }
        // Key-adjacent bool only - never use a global `<true` scan (other entitlements pollute).
        sample.getTaskAllow = entitlementBool(
            in: text,
            key: "com.apple.security.get-task-allow"
        )
        sample.disableLibraryValidation = entitlementBool(
            in: text,
            key: "com.apple.security.cs.disable-library-validation"
        )
        sample.allowDyldEnvironmentVariables = entitlementBool(
            in: text,
            key: "com.apple.security.cs.allow-dyld-environment-variables"
        )
        sample.allowUnsignedExecutableMemory = entitlementBool(
            in: text,
            key: "com.apple.security.cs.allow-unsigned-executable-memory"
        )
        if sample.signed == false {
            sample.notes.append("codesign exit=\(proc.terminationStatus)")
        }
        return sample
    }

    /// Parse a boolean entitlement from codesign XML using key-adjacent true/false only.
    ///
    /// Returns `nil` when the key is absent; `true`/`false` only when the value tag
    /// immediately follows that key (does not treat unrelated `<true/>` elsewhere as a hit).
    public static func entitlementBool(in text: String, key: String) -> Bool? {
        let escaped = NSRegularExpression.escapedPattern(for: key)
        // `<key>…key…</key>` then optional whitespace then `<true/>` or `<false/>` (or non-self-closing).
        let pattern =
            #"<key>\s*"# + escaped + #"</key>\s*<(true|false)\s*/?>"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
        else { return nil }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, options: [], range: range),
              match.numberOfRanges >= 2,
              let valueRange = Range(match.range(at: 1), in: text)
        else { return nil }
        return text[valueRange].lowercased() == "true"
    }

    private static func riskFlags(from sample: CodesignSample) -> [String] {
        var flags: [String] = []
        if sample.hardenedRuntime == false { flags.append("hardened_runtime_off") }
        if sample.getTaskAllow == true { flags.append("get-task-allow") }
        if sample.disableLibraryValidation == true { flags.append("disable-library-validation") }
        if sample.allowDyldEnvironmentVariables == true {
            flags.append("allow-dyld-environment-variables")
        }
        if sample.allowUnsignedExecutableMemory == true {
            flags.append("allow-unsigned-executable-memory")
        }
        if sample.signed == false { flags.append("unsigned_or_untrusted") }
        return flags
    }
}
