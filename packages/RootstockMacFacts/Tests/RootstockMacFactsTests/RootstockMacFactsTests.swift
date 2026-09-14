import Foundation
import XCTest
@testable import RootstockMacFacts

final class RootstockMacFactsTests: XCTestCase {
    func testHostPostureParsersAndLabels() {
        XCTAssertEqual(HostPostureProbes.parseGatekeeperOutput("assessments enabled"), true)
        XCTAssertEqual(HostPostureProbes.parseGatekeeperOutput("assessments disabled"), false)
        XCTAssertEqual(HostPostureProbes.parseSIPOutput("System Integrity Protection status: disabled."), false)
        XCTAssertEqual(HostPostureProbes.parseFileVaultOutput("Deferred enablement appears to be active."), true)
        XCTAssertNil(HostPostureProbes.parseFileVaultOutput("not a FileVault status"))
        XCTAssertEqual(HostPostureProbes.enabledLabel(nil), "unknown")
    }

    func testInjectedRunnerDefinesLiveExecutionBoundary() {
        let runner = StubPostureRunner(outputs: [
            HostPostureProbes.spctlPath: "assessments enabled",
            HostPostureProbes.csrutilPath: "System Integrity Protection status: enabled.",
            HostPostureProbes.fdesetupPath: "FileVault is Off.",
        ])

        let snapshot = HostPostureProbes.snapshot(run: runner.run)

        XCTAssertEqual(snapshot, HostPostureSnapshot(
            gatekeeperEnabled: true,
            sipEnabled: true,
            filevaultEnabled: false
        ))
        XCTAssertEqual(runner.invocations, [
            .init(path: HostPostureProbes.spctlPath, arguments: ["--status"]),
            .init(path: HostPostureProbes.csrutilPath, arguments: ["status"]),
            .init(path: HostPostureProbes.fdesetupPath, arguments: ["status"]),
        ])
    }

    func testPathCatalogAndLaunchdFactsAreDeterministic() {
        XCTAssertEqual(
            MacSecurityPaths.userTCCDatabase(homePath: "/Users/tester"),
            "/Users/tester/Library/Application Support/com.apple.TCC/TCC.db"
        )
        XCTAssertEqual(TCCServiceCatalog.displayName(for: TCCServiceCatalog.fullDiskAccessService), "Full Disk Access")
        XCTAssertTrue(TCCServiceCatalog.isKnown("kTCCServiceCamera"))
        XCTAssertEqual(TCCServiceCatalog.minimumMajorVersion(for: "kTCCServiceLocation"), 12)

        let summary = LaunchdPlistFacts.summarize(path: "fixture.plist", dict: [
            "Label": "com.example.fixture",
            "ProgramArguments": ["/usr/bin/example", "--safe"],
            "RunAtLoad": true,
            "KeepAlive": ["SuccessfulExit": false],
        ])
        XCTAssertEqual(summary.label, "com.example.fixture")
        XCTAssertEqual(summary.program, "/usr/bin/example")
        XCTAssertEqual(summary.effectiveArguments, ["/usr/bin/example", "--safe"])
        XCTAssertTrue(summary.runAtLoad)
        XCTAssertTrue(summary.keepAlive)
    }

    func testLaunchdDirectoryEnumerationAndPlistSummariesUseTemporaryFixtures() throws {
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

        XCTAssertEqual(
            LaunchdPlistFacts.listPlistPaths(in: directory.path).map { URL(fileURLWithPath: $0).lastPathComponent },
            ["alpha.plist", "broken.plist", "zeta.plist"]
        )
        let summaries = LaunchdPlistFacts.summarizeDirectory(at: directory.path)
        XCTAssertEqual(summaries.map(\.label), ["com.example.alpha", nil, "com.example.zeta"])
        XCTAssertEqual(summaries[0].effectiveArguments, ["/usr/bin/alpha", "--safe"])
        XCTAssertTrue(summaries[0].runAtLoad)
        XCTAssertFalse(summaries[1].keepAlive)
        XCTAssertTrue(summaries[2].keepAlive)
    }

    func testLaunchdKeepAliveRecognizesDocumentedShapes() {
        XCTAssertTrue(LaunchdPlistFacts.resolveKeepAlive(true))
        XCTAssertFalse(LaunchdPlistFacts.resolveKeepAlive(false))
        XCTAssertTrue(LaunchdPlistFacts.resolveKeepAlive(["SuccessfulExit": false]))
        XCTAssertFalse(LaunchdPlistFacts.resolveKeepAlive([String: Any]()))
        XCTAssertFalse(LaunchdPlistFacts.resolveKeepAlive("true"))
    }

    func testPostureParsersLeaveUnknownAndAmbiguousValuesUnknown() {
        XCTAssertNil(HostPostureProbes.parseGatekeeperOutput("status unavailable"))
        XCTAssertNil(HostPostureProbes.parseGatekeeperOutput("assessments enabled; assessments disabled"))
        XCTAssertNil(HostPostureProbes.parseSIPOutput("System Integrity Protection status: enabled then disabled"))
        XCTAssertNil(HostPostureProbes.parseFileVaultOutput("FileVault is On. FileVault is Off."))

        let unknown = HostPostureProbes.snapshot { _, _ in nil }
        XCTAssertEqual(unknown, HostPostureSnapshot())
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
