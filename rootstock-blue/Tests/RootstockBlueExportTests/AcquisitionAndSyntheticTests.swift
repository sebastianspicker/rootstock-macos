import Foundation
import XCTest
@testable import RootstockBlueAcquire
@testable import RootstockBlueCase
@testable import RootstockBlueSyntheticEvents

final class AcquisitionAndSyntheticTests: XCTestCase {
    func testMaterializationCopiesNestedRegularFilesAndCustodyHashes() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source", isDirectory: true)
        let nested = source.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try Data("fixture evidence".utf8).write(to: nested.appendingPathComponent("evidence.txt"))
        let destination = scratch.appendingPathComponent("bundle")

        let result = try LogicalAcquire.materializeFixtureBundle(from: source, to: destination, actor: "test")

        XCTAssertEqual(result.filesCopied, 1)
        XCTAssertEqual(
            try Data(contentsOf: destination.appendingPathComponent("evidence/nested/evidence.txt")),
            Data("fixture evidence".utf8)
        )
        XCTAssertNotNil(result.custodyHashes["evidence/nested/evidence.txt"])
        XCTAssertTrue(try String(contentsOf: destination.appendingPathComponent("custody.jsonl"), encoding: .utf8).contains("materialize_fixture_bundle"))
    }

    func testMaterializationRejectsOverlapsAndSymlinkEntriesWithoutPublishingStaging() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source", isDirectory: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try Data("fixture".utf8).write(to: source.appendingPathComponent("evidence.txt"))

        XCTAssertThrowsError(
            try LogicalAcquire.materializeFixtureBundle(from: source, to: source.appendingPathComponent("nested-output"))
        )

        let external = scratch.appendingPathComponent("external.txt")
        try Data("external".utf8).write(to: external)
        try FileManager.default.createSymbolicLink(at: source.appendingPathComponent("link"), withDestinationURL: external)
        let destination = scratch.appendingPathComponent("bundle")
        XCTAssertThrowsError(try LogicalAcquire.materializeFixtureBundle(from: source, to: destination))
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
        XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: scratch.path).contains { $0.contains(".bundle.rootstock-staging-") })

        let ancestorAlias = scratch.appendingPathComponent("ancestor-alias")
        try FileManager.default.createSymbolicLink(at: ancestorAlias, withDestinationURL: scratch)
        XCTAssertThrowsError(
            try LogicalAcquire.materializeFixtureBundle(
                from: ancestorAlias.appendingPathComponent("source"),
                to: scratch.appendingPathComponent("alias-bundle")
            )
        )
    }

    func testMaterializationRejectsValidatedTreeSwapBeforePublish() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source", isDirectory: true)
        let replacement = scratch.appendingPathComponent("replacement", isDirectory: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: replacement, withIntermediateDirectories: true)
        try Data("original".utf8).write(to: source.appendingPathComponent("evidence.txt"))
        try Data("replacement".utf8).write(to: replacement.appendingPathComponent("evidence.txt"))
        let destination = scratch.appendingPathComponent("bundle")

        XCTAssertThrowsError(
            try LogicalAcquire.materializeFixtureBundleForTesting(
                from: source,
                to: destination,
                afterSourceValidation: {
                    try FileManager.default.moveItem(at: source, to: scratch.appendingPathComponent("retired"))
                    try FileManager.default.moveItem(at: replacement, to: source)
                }
            )
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
    }

    func testMaterializationRejectsSameInodeContentMutationBeforePublish() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let source = scratch.appendingPathComponent("source", isDirectory: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        let evidence = source.appendingPathComponent("evidence.txt")
        try Data("original content".utf8).write(to: evidence)
        let destination = scratch.appendingPathComponent("bundle")

        XCTAssertThrowsError(
            try LogicalAcquire.materializeFixtureBundleForTesting(
                from: source,
                to: destination,
                afterSourceFileOpen: { relativePath in
                    guard relativePath == "evidence.txt" else { return }
                    let handle = try FileHandle(forWritingTo: evidence)
                    defer { try? handle.close() }
                    try handle.truncate(atOffset: 0)
                    try handle.write(contentsOf: Data("mutated content".utf8))
                }
            )
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
    }

    func testSyntheticProfilesAndLossCountersRemainExplicit() {
        let client = SyntheticEventClient()
        let profile = SyntheticEventProfile.builtin(.research)
        client.start(profile: profile)
        XCTAssertEqual(client.profile?.name, .research)
        XCTAssertTrue(profile.eventTypes.contains("NOTIFY_XPC_CONNECT"))

        client.injectSyntheticRaw([
            ["event_type": "NOTIFY_EXEC", "process_path": "/tmp/fixture"],
            ["process_path": "/tmp/malformed"],
        ])
        XCTAssertEqual(client.pollEvents().count, 1)
        XCTAssertEqual(client.counters.received, 2)
        XCTAssertEqual(client.counters.mapped, 1)
        XCTAssertEqual(client.counters.mapFailures, 1)
        XCTAssertEqual(client.counters.totalDropped, 1)

        let buffer = RingBuffer<Int>(capacity: 1)
        XCTAssertTrue(buffer.enqueue(1))
        XCTAssertFalse(buffer.enqueue(2))
        XCTAssertEqual(buffer.snapshotCounters().droppedBackpressure, 1)
    }
}
