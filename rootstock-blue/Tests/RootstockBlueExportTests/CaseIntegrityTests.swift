import Darwin
import Dispatch
import XCTest
@testable import RootstockBlueCase
@testable import RootstockBlueCollect
@testable import RootstockBlueCore
@testable import RootstockBlueExport

final class CaseIntegrityTests: XCTestCase {
    func testCaseIntegrityCoversEvidenceAndTimelineProjection() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let package = try CasePackage.create(at: scratch.appendingPathComponent("case.rsbcase"))
        let event = sampleEvent()

        try package.appendEvent(event, stream: "es")
        let artifact = scratch.appendingPathComponent("artifact.txt")
        try Data("evidence".utf8).write(to: artifact)
        _ = try package.copyArtifact(from: artifact, relativeName: "evidence/artifact.txt")

        XCTAssertNoThrow(try package.verifyIntegrity())
        let checksums = try String(contentsOf: package.sha256sumsURL, encoding: .utf8)
        XCTAssertTrue(checksums.contains("  artifacts/evidence/artifact.txt\n"))
        XCTAssertTrue(checksums.contains("  events/es/2026-08-27.jsonl\n"))
    }

    func testCaseIntegrityRejectsTamperingAndInjectedPartialWrites() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let package = try CasePackage.create(at: scratch.appendingPathComponent("case.rsbcase"))

        try package.appendEvent(sampleEvent(), stream: "es")
        var tamperedCustody = try Data(contentsOf: package.custodyURL)
        tamperedCustody.append(Data("tampered".utf8))
        try tamperedCustody.write(to: package.custodyURL)
        XCTAssertThrowsError(try package.verifyIntegrity())
        XCTAssertThrowsError(
            try package.appendCustody(CustodyEvent(actor: "test", action: "must_not_reseal"))
        )

        let tamperedEvent = try CasePackage.create(at: scratch.appendingPathComponent("tampered-event.rsbcase"))
        var tamperedEventCustody = try Data(contentsOf: tamperedEvent.custodyURL)
        tamperedEventCustody.append(Data("tampered".utf8))
        try tamperedEventCustody.write(to: tamperedEvent.custodyURL)
        XCTAssertThrowsError(try tamperedEvent.appendEvent(sampleEvent(), stream: "es"))

        let interrupted = try CasePackage.create(at: scratch.appendingPathComponent("interrupted.rsbcase"))
        XCTAssertThrowsError(
            try interrupted.appendEventBatch(
                [sampleEvent(), sampleEvent(id: "D5EA2CEF-5D6A-4206-ABCB-74DCFA1AC779")],
                stream: "es",
                custody: nil,
                afterEventWrite: { index in if index == 0 { throw InjectedWriteFailure.expected } }
            )
        )
        XCTAssertThrowsError(try interrupted.verifyIntegrity())
    }

    func testCaseRejectsDuplicateEventsAndUnsafeOrOverwrittenArtifacts() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let package = try CasePackage.create(at: scratch.appendingPathComponent("case.rsbcase"))
        let source = scratch.appendingPathComponent("source.txt")
        try Data("evidence".utf8).write(to: source)

        XCTAssertThrowsError(try package.appendEventBatch([sampleEvent(), sampleEvent()], stream: "es", custody: nil))
        XCTAssertNoThrow(try package.verifyIntegrity())
        XCTAssertThrowsError(try package.copyArtifact(from: source, relativeName: "../escape.txt"))
        XCTAssertThrowsError(try package.copyArtifact(from: source, relativeName: "/absolute.txt"))
        _ = try package.copyArtifact(from: source, relativeName: "safe/source.txt")
        XCTAssertThrowsError(try package.copyArtifact(from: source, relativeName: "safe/source.txt"))

        let interrupted = try CasePackage.create(at: scratch.appendingPathComponent("artifact.rsbcase"))
        XCTAssertThrowsError(
            try interrupted.copyArtifact(from: source, relativeName: "safe/source.txt", afterStagedCopy: {
                throw InjectedWriteFailure.expected
            })
        )
        XCTAssertThrowsError(try interrupted.verifyIntegrity())
    }

    func testConcurrentDuplicateWriterFailsBeforeMutationAndLeavesCaseVerified() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let package = try CasePackage.create(at: scratch.appendingPathComponent("case.rsbcase"))
        let duplicate = sampleEvent()
        let readyToRace = DispatchSemaphore(value: 0)
        let allowSecondWriter = DispatchSemaphore(value: 0)
        let secondWriterFinished = DispatchSemaphore(value: 0)
        let failure = LockedErrorBox()

        DispatchQueue.global().async {
            defer { secondWriterFinished.signal() }
            do {
                try package.appendEventBatch(
                    [duplicate],
                    stream: "es",
                    custody: nil,
                    afterEventWrite: nil,
                    beforeWriteLock: {
                        readyToRace.signal()
                        guard allowSecondWriter.wait(timeout: .now() + 5) == .success else {
                            throw InjectedWriteFailure.expected
                        }
                    }
                )
            } catch {
                failure.record(error)
            }
        }

        XCTAssertEqual(readyToRace.wait(timeout: .now() + 5), .success)
        try package.appendEvent(duplicate, stream: "es")
        allowSecondWriter.signal()
        XCTAssertEqual(secondWriterFinished.wait(timeout: .now() + 5), .success)

        XCTAssertNotNil(failure.value)
        XCTAssertEqual(try package.loadAllEvents().count, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: package.rootURL.appendingPathComponent(".rsbcase-write-lock").path))
        XCTAssertNoThrow(try package.verifyIntegrity())
    }

    func testUnsupportedCaseFormatFailsBeforeOpenOrVerificationMutatesCase() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }

        for (suffix, version) in [("negative", Optional<Any>.some(-1)), ("future", Optional<Any>.some(1)), ("missing", nil), ("wrong-type", Optional<Any>.some("zero"))] {
            let package = try CasePackage.create(at: scratch.appendingPathComponent("\(suffix).rsbcase"))
            let originalChecksums = try Data(contentsOf: package.sha256sumsURL)
            let originalCustody = try Data(contentsOf: package.custodyURL)
            var manifest = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(contentsOf: package.manifestURL)) as? [String: Any]
            )
            if let version {
                manifest["formatVersion"] = version
            } else {
                manifest.removeValue(forKey: "formatVersion")
            }
            try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys]).write(to: package.manifestURL)

            XCTAssertThrowsError(try CasePackage.open(at: package.rootURL)) { error in
                if suffix == "negative" || suffix == "future" {
                    XCTAssertTrue(error.localizedDescription.contains("unsupported case package format version"))
                }
            }
            XCTAssertThrowsError(try package.verifyIntegrity())
            XCTAssertEqual(try Data(contentsOf: package.sha256sumsURL), originalChecksums)
            XCTAssertEqual(try Data(contentsOf: package.custodyURL), originalCustody)
        }
    }

    func testCollectionPackRejectsUnsafeNamesAndArtifactPaths() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let pack = scratch.appendingPathComponent("unsafe.yaml")
        try """
        name: ../unsafe
        artifacts:
          - ../../etc/passwd
        """.write(to: pack, atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try CollectionPackLoader.load(from: pack))

        let safePack = scratch.appendingPathComponent("safe.yaml")
        try """
        name: incident_01
        artifacts:
          - logs/system.log
        """.write(to: safePack, atomically: true, encoding: .utf8)
        XCTAssertNoThrow(try CollectionPackLoader.load(from: safePack))
    }

    func testCollectionRejectsSymlinkRootsAndSourceComponents() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let package = try CasePackage.create(at: scratch.appendingPathComponent("case.rsbcase"))
        let pack = CollectionPack(
            name: "fixture",
            description: "fixture",
            requiresFDA: false,
            artifacts: ["logs/evidence.txt"]
        )
        let root = scratch.appendingPathComponent("source", isDirectory: true)
        let logs = root.appendingPathComponent("logs", isDirectory: true)
        try FileManager.default.createDirectory(at: logs, withIntermediateDirectories: true)
        try Data("evidence".utf8).write(to: logs.appendingPathComponent("evidence.txt"))
        let runner = CollectRunner(skipStrictPreflight: true)

        let rootAlias = scratch.appendingPathComponent("root-alias")
        try FileManager.default.createSymbolicLink(at: rootAlias, withDestinationURL: root)
        XCTAssertThrowsError(try runner.run(pack: pack, sourceRoot: rootAlias, into: package))

        let ancestor = scratch.appendingPathComponent("ancestor", isDirectory: true)
        try FileManager.default.createDirectory(at: ancestor, withIntermediateDirectories: true)
        let nestedRoot = ancestor.appendingPathComponent("nested-source", isDirectory: true)
        try FileManager.default.copyItem(at: root, to: nestedRoot)
        let ancestorAlias = scratch.appendingPathComponent("ancestor-alias")
        try FileManager.default.createSymbolicLink(at: ancestorAlias, withDestinationURL: ancestor)
        XCTAssertThrowsError(
            try runner.run(
                pack: pack,
                sourceRoot: ancestorAlias.appendingPathComponent("nested-source"),
                into: package
            )
        )

        let external = scratch.appendingPathComponent("external", isDirectory: true)
        try FileManager.default.createDirectory(at: external, withIntermediateDirectories: true)
        try Data("external".utf8).write(to: external.appendingPathComponent("evidence.txt"))
        try FileManager.default.removeItem(at: logs)
        try FileManager.default.createSymbolicLink(at: logs, withDestinationURL: external)
        XCTAssertThrowsError(try runner.run(pack: pack, sourceRoot: root.resolvingSymlinksInPath(), into: package))
        XCTAssertNoThrow(try package.verifyIntegrity())
    }

    func testCollectionStreamsOpenedDescriptorAcrossSynchronizedParentSwap() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let package = try CasePackage.create(at: scratch.appendingPathComponent("case.rsbcase"))
        let sourceRoot = scratch.appendingPathComponent("source", isDirectory: true)
        let sourceTCC = sourceRoot.appendingPathComponent("Library/Application Support/com.apple.TCC/TCC.db")
        try FileManager.default.createDirectory(at: sourceTCC.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("inside-case-source".utf8).write(to: sourceTCC)

        let outsideRoot = scratch.appendingPathComponent("outside", isDirectory: true)
        let outsideTCC = outsideRoot.appendingPathComponent("Application Support/com.apple.TCC/TCC.db")
        try FileManager.default.createDirectory(at: outsideTCC.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("outside-readme-bytes".utf8).write(to: outsideTCC)

        let pack = CollectionPack(
            name: "tcc",
            description: "fixture",
            requiresFDA: false,
            artifacts: ["tcc"]
        )
        let runner = CollectRunner(skipStrictPreflight: true)
        let result = try runner.run(
            pack: pack,
            sourceRoot: sourceRoot.resolvingSymlinksInPath(),
            into: package,
            afterSourceFileOpen: { relativePath in
                guard relativePath == "Library/Application Support/com.apple.TCC/TCC.db" else { return }
                let library = sourceRoot.appendingPathComponent("Library")
                try FileManager.default.removeItem(at: library)
                try FileManager.default.createSymbolicLink(at: library, withDestinationURL: outsideRoot)
            }
        )

        XCTAssertEqual(result.filesCopied, 1)
        let copied = package.artifactsURL.appendingPathComponent("tcc/Library/Application Support/com.apple.TCC/TCC.db")
        XCTAssertEqual(try Data(contentsOf: copied), Data("inside-case-source".utf8))
        XCTAssertNotEqual(try Data(contentsOf: copied), Data("outside-readme-bytes".utf8))
        XCTAssertNoThrow(try package.verifyIntegrity())
    }

    func testCollectionDeduplicatesOverlappingStockArtifactMappings() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let package = try CasePackage.create(at: scratch.appendingPathComponent("case.rsbcase"))
        let sourceRoot = scratch.appendingPathComponent("source", isDirectory: true)
        let shared = sourceRoot.appendingPathComponent("Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist")
        try FileManager.default.createDirectory(at: shared.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("network-context".utf8).write(to: shared)
        let pack = CollectionPack(
            name: "network",
            description: "fixture",
            requiresFDA: false,
            artifacts: ["wifi", "netlocation"]
        )

        let result = try CollectRunner(skipStrictPreflight: true).run(
            pack: pack,
            sourceRoot: sourceRoot.resolvingSymlinksInPath(),
            into: package
        )
        XCTAssertEqual(result.filesCopied, 1)
        XCTAssertNoThrow(try package.verifyIntegrity())
    }

    func testCaseRejectsSymlinkedRequiredEntriesAndSpecialInventoryNodes() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let checksumCase = try CasePackage.create(at: scratch.appendingPathComponent("checksum.rsbcase"))
        let external = scratch.appendingPathComponent("external.txt")
        try Data("external".utf8).write(to: external)
        try FileManager.default.removeItem(at: checksumCase.sha256sumsURL)
        try FileManager.default.createSymbolicLink(at: checksumCase.sha256sumsURL, withDestinationURL: external)
        XCTAssertThrowsError(try checksumCase.verifyIntegrity())

        let rootCase = try CasePackage.create(at: scratch.appendingPathComponent("root.rsbcase"))
        try FileManager.default.removeItem(at: rootCase.eventsESURL)
        try FileManager.default.createSymbolicLink(at: rootCase.eventsESURL, withDestinationURL: external)
        XCTAssertThrowsError(try rootCase.verifyIntegrity())

        let specialCase = try CasePackage.create(at: scratch.appendingPathComponent("special.rsbcase"))
        let fifo = specialCase.artifactsURL.appendingPathComponent("unexpected.fifo")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        XCTAssertThrowsError(try specialCase.verifyIntegrity())
    }

    func testCaseExportsPreserveInputCaseForDirectAndSymlinkAliasOutputs() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let package = try CasePackage.create(at: scratch.appendingPathComponent("case.rsbcase"))
        try package.appendEvent(sampleEvent())

        let directOutput = package.rootURL.appendingPathComponent("report.md")
        XCTAssertThrowsError(try CaseReport.exportMarkdown(package: package, to: directOutput))
        XCTAssertFalse(FileManager.default.fileExists(atPath: directOutput.path))
        XCTAssertNoThrow(try package.verifyIntegrity())

        let caseAlias = scratch.appendingPathComponent("case-alias.rsbcase")
        try FileManager.default.createSymbolicLink(at: caseAlias, withDestinationURL: package.rootURL)
        let aliasOutput = caseAlias.appendingPathComponent("report.md")
        XCTAssertThrowsError(try CaseReport.exportMarkdown(package: package, to: aliasOutput))
        XCTAssertFalse(FileManager.default.fileExists(atPath: package.rootURL.appendingPathComponent("report.md").path))
        XCTAssertNoThrow(try package.verifyIntegrity())

        let existingOutput = scratch.appendingPathComponent("existing.jsonl")
        try Data("preserve".utf8).write(to: existingOutput)
        XCTAssertThrowsError(
            try JSONLExporter.exportCase(package, to: existingOutput)
        )
        XCTAssertEqual(try Data(contentsOf: existingOutput), Data("preserve".utf8))
        XCTAssertNoThrow(try package.verifyIntegrity())
    }

    func testScanImportComposesAllFamilyNodesWithCanonicalPersistenceFields() throws {
        let fixture = try familyExportFixture()
        let export = FamilyOpenExporter.build(events: fixture.events, caseName: "fallback-case", generatedAt: fixture.eventTime)
        let repeatedExport = FamilyOpenExporter.build(events: fixture.events, caseName: "fallback-case", generatedAt: fixture.eventTime)
        XCTAssertEqual(
            try JSONSerialization.data(withJSONObject: export, options: [.sortedKeys]),
            try JSONSerialization.data(withJSONObject: repeatedExport, options: [.sortedKeys])
        )
        let nodes = try XCTUnwrap(export["nodes"] as? [[String: Any]])
        let node = { (type: String) in nodes.first { $0["type"] as? String == type } }

        let host = try XCTUnwrap(node("Host"))
        XCTAssertEqual(host["hostname"] as? String, "collector-host")
        let launch = try XCTUnwrap(node("LaunchItem"))
        XCTAssertEqual(launch["label"] as? String, "com.example.fixture")
        XCTAssertEqual(launch["path"] as? String, "/Library/LaunchAgents/com.example.fixture.plist")
        XCTAssertEqual(launch["program"] as? String, "/Applications/Fixture.app/Contents/MacOS/fixture")
        let collisionLaunches = nodes.filter { ($0["label"] as? String) == "a/b" || ($0["label"] as? String) == "a?b" }
        XCTAssertEqual(collisionLaunches.count, 2)
        XCTAssertEqual(Set(collisionLaunches.compactMap { $0["id"] as? String }).count, 2)
        XCTAssertNotNil(node("Protection"))
        XCTAssertNotNil(node("Finding"))

        let importedLaunch = try XCTUnwrap(fixture.imported.first { $0.eventType == EventVocabulary.persistenceLaunchItem })
        XCTAssertEqual(importedLaunch.fields[FieldTaxonomy.persistenceLabel], "com.example.fixture")
        XCTAssertEqual(importedLaunch.fields[FieldTaxonomy.persistencePath], "/Library/LaunchAgents/com.example.fixture.plist")
        XCTAssertEqual(importedLaunch.fields[FieldTaxonomy.persistenceProgram], "/Applications/Fixture.app/Contents/MacOS/fixture")
        XCTAssertNil(importedLaunch.fields["persist.label"])
    }

    private func familyExportFixture() throws -> (events: [EventEnvelope], imported: [EventEnvelope], eventTime: Date) {
        let imported = try ScanJSONImporter.events(from: try familyScanData()).events
        let eventTime = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-08-27T12:00:00Z"))
        return (
            imported + familySyntheticEvents(eventTime: eventTime),
            imported,
            eventTime
        )
    }

    private func familyScanData() throws -> Data {
        try XCTUnwrap(
            """
            {
              "scan_id": "family-fixture-1",
              "timestamp": "2026-08-27T12:00:00Z",
              "hostname": "collector-host",
              "tcc_grants": [],
              "launch_items": [{
                "label": "com.example.fixture",
                "path": "/Library/LaunchAgents/com.example.fixture.plist",
                "program": "/Applications/Fixture.app/Contents/MacOS/fixture",
                "type": "agent"
              }]
            }
            """.data(using: .utf8)
        )
    }

    private func familySyntheticEvents(eventTime: Date) -> [EventEnvelope] {
        [familyProtection(eventTime: eventTime), familyFinding(eventTime: eventTime)]
            + familyPersistenceCollisions(eventTime: eventTime)
    }

    private func familyProtection(eventTime: Date) -> EventEnvelope {
        EventEnvelope(
            identity: .init(kind: EventVocabulary.postureProtection, label: "fixture"),
            capture: .init(source: .synthetic, eventTime: eventTime),
            payload: .init(properties: [
                FieldTaxonomy.eventType: EventVocabulary.postureProtection,
                "protection.name": "Gatekeeper", "protection.enabled": "present",
            ])
        )
    }

    private func familyFinding(eventTime: Date) -> EventEnvelope {
        EventEnvelope(
            identity: .init(kind: EventVocabulary.importedFinding, label: "fixture"),
            capture: .init(source: .synthetic, eventTime: eventTime),
            payload: .init(properties: [
                FieldTaxonomy.eventType: EventVocabulary.importedFinding,
                "finding.id": "fixture.finding", "finding.title": "Fixture finding", "finding.severity": "high",
            ])
        )
    }

    private func familyPersistenceCollisions(eventTime: Date) -> [EventEnvelope] {
        [
            familyPersistenceEvent(id: "B2B6F9D6-A4BE-4A03-92DE-9A876F2B76AF", label: "a/b", path: "/Library/LaunchAgents/a-b-one.plist", program: "/tmp/a-b-one", eventTime: eventTime),
            familyPersistenceEvent(id: "D21B35E6-20BB-46FD-8EE4-2CA6FB8423A9", label: "a?b", path: "/Library/LaunchAgents/a-b-two.plist", program: "/tmp/a-b-two", eventTime: eventTime),
        ]
    }

    private func familyPersistenceEvent(id: String, label: String, path: String, program: String, eventTime: Date) -> EventEnvelope {
        EventEnvelope(
            identity: .init(id: UUID(uuidString: id)!, kind: EventVocabulary.persistenceLaunchItem, label: "fixture"),
            capture: .init(source: .synthetic, eventTime: eventTime),
            payload: .init(properties: [
                FieldTaxonomy.eventType: EventVocabulary.persistenceLaunchItem,
                FieldTaxonomy.persistenceLabel: label,
                FieldTaxonomy.persistencePath: path,
                FieldTaxonomy.persistenceProgram: program,
            ])
        )
    }

    private func sampleEvent(id: String = "8EBE8993-8CFF-422E-8E6A-5845D60D42EE") -> EventEnvelope {
        EventEnvelope(
            identity: .init(
                id: UUID(uuidString: id)!,
                kind: "fixture.event",
                label: "TEST"
            ),
            capture: .init(
                source: .synthetic,
                eventTime: ISO8601DateFormatter().date(from: "2026-08-27T12:00:00Z")!,
                collectedAt: ISO8601DateFormatter().date(from: "2026-08-27T12:00:01Z")!
            ),
            payload: .init(properties: ["fixture": "true"])
        )
    }
}

private enum InjectedWriteFailure: Error {
    case expected
}

private final class LockedErrorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Error?

    func record(_ error: Error) {
        lock.lock()
        stored = error
        lock.unlock()
    }

    var value: Error? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }
}
