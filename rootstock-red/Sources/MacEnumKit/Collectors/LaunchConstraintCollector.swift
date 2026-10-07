import Foundation
import Darwin
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
        let captureURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-codesign-\(UUID().uuidString)")
        do {
            try Data().write(to: captureURL, options: .withoutOverwriting)
        } catch {
            sample.notes.append("codesign capture setup failed: \(error.localizedDescription)")
            return sample
        }
        defer { try? FileManager.default.removeItem(at: captureURL) }
        _ = chmod(captureURL.path, mode_t(S_IRUSR | S_IWUSR))

        switch runCodesign(path: path, capturingTo: captureURL) {
        case .failed(let note):
            sample.notes.append(note)
            return sample
        case .completed(let status):
            applyCodesignOutput(from: captureURL, status: status, to: &sample)
            return sample
        }
    }

    private enum CodesignRunOutcome {
        case completed(Int32)
        case failed(String)
    }

    private static func runCodesign(path: String, capturingTo captureURL: URL) -> CodesignRunOutcome {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        proc.arguments = ["-dvv", "--entitlements", ":-", path]
        guard let capture = try? FileHandle(forWritingTo: captureURL) else {
            return .failed("codesign capture open failed")
        }
        proc.standardOutput = capture
        proc.standardError = capture
        let completed = DispatchSemaphore(value: 0)
        proc.terminationHandler = { _ in completed.signal() }
        do {
            try proc.run()
        } catch {
            try? capture.close()
            return .failed("codesign spawn failed: \(error.localizedDescription)")
        }
        let outputLimit = 2 * 1024 * 1024
        let deadline = Date().addingTimeInterval(5)
        var timedOut = false
        var outputExceeded = false
        while completed.wait(timeout: .now() + .milliseconds(50)) == .timedOut {
            var info = stat()
            if fstat(capture.fileDescriptor, &info) == 0, info.st_size > outputLimit {
                outputExceeded = true
                break
            }
            if Date() >= deadline {
                timedOut = true
                break
            }
        }
        if timedOut || outputExceeded {
            proc.terminate()
            if completed.wait(timeout: .now() + 1) == .timedOut {
                kill(proc.processIdentifier, SIGKILL)
                _ = completed.wait(timeout: .now() + 1)
            }
            try? capture.close()
            return .failed(timedOut ? "codesign probe timed out" : "codesign output exceeded size limit")
        }
        try? capture.close()
        return .completed(proc.terminationStatus)
    }

    private static func applyCodesignOutput(
        from captureURL: URL,
        status: Int32,
        to sample: inout CodesignSample
    ) {
        let outputLimit = 2 * 1024 * 1024
        let reader = try? FileHandle(forReadingFrom: captureURL)
        let captured = (try? reader?.read(upToCount: outputLimit + 1)) ?? Data()
        try? reader?.close()
        let bounded = captured.prefix(outputLimit)
        let text = String(data: Data(bounded), encoding: .utf8) ?? ""
        if captured.count > outputLimit {
            sample.notes.append("codesign output truncated")
        }
        sample.signed = status == 0 || text.contains("\nAuthority=") || text.hasPrefix("Authority=")
        // `-dvv` prints `flags=0x10000(runtime)` on the CodeDirectory line (stderr, captured with stdout).
        if let flagsLine = text.split(whereSeparator: \.isNewline).first(where: { $0.contains("flags=0x") }) {
            sample.hardenedRuntime = flagsLine.contains("runtime")
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
            sample.notes.append("codesign exit=\(status)")
        }
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
