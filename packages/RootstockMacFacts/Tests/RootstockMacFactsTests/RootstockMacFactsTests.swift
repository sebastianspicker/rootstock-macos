import Foundation
import Testing
@testable import RootstockMacFacts

@Suite struct RootstockMacFactsTests {
    @Test func hostPostureParsersAndLabels() {
        #expect(HostPostureProbes.parseGatekeeperOutput("assessments enabled") == true)
        #expect(HostPostureProbes.parseGatekeeperOutput("assessments disabled") == false)
        #expect(HostPostureProbes.parseSIPOutput("System Integrity Protection status: disabled.") == false)
        #expect(HostPostureProbes.parseFileVaultOutput("Deferred enablement appears to be active.") == true)
        #expect(HostPostureProbes.parseFileVaultOutput("not a FileVault status") == nil)
        #expect(HostPostureProbes.enabledLabel(nil) == "unknown")
    }

    @Test func injectedRunnerDefinesLiveExecutionBoundary() {
        let runner = StubPostureRunner(outputs: [
            HostPostureProbes.spctlPath: "assessments enabled",
            HostPostureProbes.csrutilPath: "System Integrity Protection status: enabled.",
            HostPostureProbes.fdesetupPath: "FileVault is Off.",
        ])

        let snapshot = HostPostureProbes.snapshot(run: runner.run)

        #expect(snapshot == HostPostureSnapshot(
            gatekeeperEnabled: true,
            sipEnabled: true,
            filevaultEnabled: false
        ))
        #expect(runner.invocations == [
            .init(path: HostPostureProbes.spctlPath, arguments: ["--status"]),
            .init(path: HostPostureProbes.csrutilPath, arguments: ["status"]),
            .init(path: HostPostureProbes.fdesetupPath, arguments: ["status"]),
        ])
    }

    @Test func pathCatalogAndLaunchdFactsAreDeterministic() {
        #expect(MacSecurityPaths.userTCCDatabase(homePath: "/Users/tester") == "/Users/tester/Library/Application Support/com.apple.TCC/TCC.db")
        #expect(TCCServiceCatalog.displayName(for: TCCServiceCatalog.fullDiskAccessService) == "Full Disk Access")
        #expect(TCCServiceCatalog.isKnown("kTCCServiceCamera"))
        #expect(TCCServiceCatalog.minimumMajorVersion(for: "kTCCServiceLocation") == 12)

        let summary = LaunchdPlistFacts.summarize(path: "fixture.plist", dict: [
            "Label": "com.example.fixture",
            "ProgramArguments": ["/usr/bin/example", "--safe"],
            "RunAtLoad": true,
            "KeepAlive": ["SuccessfulExit": false],
        ])
        #expect(summary.label == "com.example.fixture")
        #expect(summary.program == "/usr/bin/example")
        #expect(summary.effectiveArguments == ["/usr/bin/example", "--safe"])
        #expect(summary.runAtLoad)
        #expect(summary.keepAlive)
    }

    @Test func launchdDirectoryEnumerationAndPlistSummariesUseTemporaryFixtures() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try writePlist(
            [
                "Label": "com.example.zeta",
                "Program": "/usr/local/bin/zeta",
                "KeepAlive": true,
            ],
            to: directory.appendingPathComponent("zeta.plist")
        )
        try writePlist(
            [
                "Label": "com.example.alpha",
                "ProgramArguments": ["/usr/bin/alpha", "--safe"],
                "RunAtLoad": true,
            ],
            to: directory.appendingPathComponent("alpha.plist")
        )
        try Data("not a plist".utf8).write(to: directory.appendingPathComponent("broken.plist"))
        try Data().write(to: directory.appendingPathComponent("ignored.txt"))

        #expect(LaunchdPlistFacts.listPlistPaths(in: directory.path).map { URL(fileURLWithPath: $0).lastPathComponent } == ["alpha.plist", "broken.plist", "zeta.plist"])
        let summaries = LaunchdPlistFacts.summarizeDirectory(at: directory.path)
        #expect(summaries.map(\.label) == ["com.example.alpha", nil, "com.example.zeta"])
        #expect(summaries[0].effectiveArguments == ["/usr/bin/alpha", "--safe"])
        #expect(summaries[0].runAtLoad)
        #expect(!(summaries[1].keepAlive))
        #expect(summaries[2].keepAlive)
    }

    @Test func launchdKeepAliveRecognizesDocumentedShapes() {
        #expect(LaunchdPlistFacts.resolveKeepAlive(true))
        #expect(!(LaunchdPlistFacts.resolveKeepAlive(false)))
        #expect(LaunchdPlistFacts.resolveKeepAlive(["SuccessfulExit": false]))
        #expect(!(LaunchdPlistFacts.resolveKeepAlive([String: Any]())))
        #expect(!(LaunchdPlistFacts.resolveKeepAlive("true")))
    }

    @Test func postureParsersLeaveUnknownAndAmbiguousValuesUnknown() {
        #expect(HostPostureProbes.parseGatekeeperOutput("status unavailable") == nil)
        #expect(HostPostureProbes.parseGatekeeperOutput("assessments enabled; assessments disabled") == nil)
        #expect(HostPostureProbes.parseSIPOutput("System Integrity Protection status: enabled then disabled") == nil)
        #expect(HostPostureProbes.parseFileVaultOutput("FileVault is On. FileVault is Off.") == nil)

        let unknown = HostPostureProbes.snapshot { _, _ in nil }
        #expect(unknown == HostPostureSnapshot())
    }

    private func makeTemporaryDirectory() throws -> URL {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("rootstock-macfacts-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func writePlist(_ dictionary: [String: Any], to url: URL) throws {
        let data = try PropertyListSerialization.data(
            fromPropertyList: dictionary,
            format: .xml,
            options: 0
        )
        try data.write(to: url)
    }
}

private final class StubPostureRunner: @unchecked Sendable {
    struct Invocation: Equatable {
        let path: String
        let arguments: [String]
    }

    private let outputs: [String: String]
    private let lock = NSLock()
    private var recordedInvocations: [Invocation] = []

    init(outputs: [String: String]) {
        self.outputs = outputs
    }

    var invocations: [Invocation] {
        lock.lock()
        defer { lock.unlock() }
        return recordedInvocations
    }

    func run(path: String, arguments: [String]) -> String? {
        lock.lock()
        recordedInvocations.append(.init(path: path, arguments: arguments))
        lock.unlock()
        return outputs[path]
    }
}
