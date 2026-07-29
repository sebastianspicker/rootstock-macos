import XCTest
@testable import RootstockBlueAcquire
@testable import RootstockBlueCase
@testable import RootstockBlueCore

final class AcquireExpansionTests: XCTestCase {
    func testPreflightHonestNonGoals() {
        let report = AcquisitionPreflight.report()
        XCTAssertTrue(report.capabilities.contains { $0.name.contains("Logical") && $0.available })
        XCTAssertTrue(report.capabilities.contains { $0.name.contains("FileVault") && !$0.available })
        XCTAssertTrue(report.capabilities.contains { $0.name.contains("Secure Enclave") && !$0.available })
        XCTAssertTrue(report.capabilities.contains { $0.name.contains("RAM") && !$0.available })
        XCTAssertTrue(report.nonGoals.contains { $0.lowercased().contains("filevault") })
        XCTAssertTrue(report.summaryLines.joined(separator: "\n").contains("cannot"))
    }

    func testPlanDocumentsNonGoals() {
        let dest = URL(fileURLWithPath: "/tmp/rsb-acquire-plan")
        let plan = LogicalAcquire.plan(destination: dest)
        XCTAssertFalse(plan.steps.isEmpty)
        XCTAssertTrue(plan.nonGoals.contains { $0.lowercased().contains("filevault") })
        XCTAssertFalse(plan.notes.isEmpty)
    }

    func testMaterializeFixtureBundleHashesTree() throws {
        let fixture = URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixture.path))
        let dest = FileManager.default.temporaryDirectory
            .appendingPathComponent("rsb-acq-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dest) }

        let result = try LogicalAcquire.materializeFixtureBundle(from: fixture, to: dest)
        XCTAssertGreaterThan(result.filesCopied, 5)
        XCTAssertGreaterThan(result.custodyHashes.count, 5)
        XCTAssertTrue(FileManager.default.fileExists(atPath: dest.appendingPathComponent("acquisition_manifest.json").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: dest.appendingPathComponent("sha256sums.txt").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: dest.appendingPathComponent("custody.jsonl").path))

        let data = try Data(contentsOf: dest.appendingPathComponent("acquisition_manifest.json"))
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let nonGoals = json?["non_goals"] as? [String] ?? []
        XCTAssertTrue(nonGoals.contains { $0.lowercased().contains("filevault") })
    }

    func testMaterializeFixtureBundleRefusesExistingDestinationWithoutChangingIt() throws {
        let fixture = URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixture.path))
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("rsb-acq-existing-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: destination) }
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        let sentinel = destination.appendingPathComponent("keep.txt")
        try "preserve this evidence".write(to: sentinel, atomically: true, encoding: .utf8)

        XCTAssertThrowsError(try LogicalAcquire.materializeFixtureBundle(from: fixture, to: destination)) { error in
            XCTAssertTrue(error.localizedDescription.contains("will not be modified"))
        }
        XCTAssertEqual(try String(contentsOf: sentinel, encoding: .utf8), "preserve this evidence")
    }

    func testMaterializeFixtureBundleRefusesDanglingDestinationSymlink() throws {
        let fixture = URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixture.path))
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("rsb-acq-dangling-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: destination) }
        try FileManager.default.createSymbolicLink(
            at: destination,
            withDestinationURL: destination.deletingLastPathComponent().appendingPathComponent("missing-target")
        )

        XCTAssertThrowsError(try LogicalAcquire.materializeFixtureBundle(from: fixture, to: destination)) { error in
            XCTAssertTrue(error.localizedDescription.contains("will not be modified"))
        }
        XCTAssertNoThrow(try FileManager.default.destinationOfSymbolicLink(atPath: destination.path))
    }

    func testMaterializeFixtureBundleRefusesDestinationInsideSourceWithoutResidue() throws {
        let source = try temporaryDirectory(prefix: "rsb-acq-source")
        defer { try? FileManager.default.removeItem(at: source) }
        try "fixture".write(
            to: source.appendingPathComponent("evidence.txt"),
            atomically: true,
            encoding: .utf8
        )
        let destination = source.appendingPathComponent("output")

        XCTAssertThrowsError(try LogicalAcquire.materializeFixtureBundle(from: source, to: destination)) { error in
            XCTAssertTrue(error.localizedDescription.contains("must not overlap"))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
        XCTAssertTrue(try stagingDirectories(near: destination).isEmpty)
    }

    func testMaterializeFixtureBundleRejectsSymlinkDescendantWithoutResidue() throws {
        let source = try temporaryDirectory(prefix: "rsb-acq-symlink-source")
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("rsb-acq-symlink-destination-\(UUID().uuidString)")
        defer {
            try? FileManager.default.removeItem(at: source)
            try? FileManager.default.removeItem(at: destination)
        }
        try "fixture".write(
            to: source.appendingPathComponent("evidence.txt"),
            atomically: true,
            encoding: .utf8
        )
        try FileManager.default.createSymbolicLink(
            at: source.appendingPathComponent("linked-evidence.txt"),
            withDestinationURL: source.appendingPathComponent("evidence.txt")
        )

        XCTAssertThrowsError(try LogicalAcquire.materializeFixtureBundle(from: source, to: destination)) { error in
            XCTAssertTrue(error.localizedDescription.contains("symbolic link"))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
        XCTAssertTrue(try stagingDirectories(near: destination).isEmpty)
    }

    func testMaterializeFixtureBundleWritesValidCustodyJSONForEscapedActor() throws {
        let fixture = URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixture.path))
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("rsb-acq-custody-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: destination) }
        let actor = "analyst \"one\"\nshift-b"

        _ = try LogicalAcquire.materializeFixtureBundle(from: fixture, to: destination, actor: actor)

        let custodyURL = destination.appendingPathComponent("custody.jsonl")
        let data = try Data(contentsOf: custodyURL)
        let line = try XCTUnwrap(String(data: data, encoding: .utf8)?.split(separator: "\n").first)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
        XCTAssertEqual(json["actor"] as? String, actor)
        XCTAssertEqual(json["action"] as? String, "materialize_fixture_bundle")
    }

    func testAcquisitionWizardRefusesExistingCaseWithoutChangingIt() throws {
        let outputCase = FileManager.default.temporaryDirectory
            .appendingPathComponent("rsb-case-existing-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: outputCase) }
        try FileManager.default.createDirectory(at: outputCase, withIntermediateDirectories: true)
        let sentinel = outputCase.appendingPathComponent("keep.txt")
        try "preserve this case".write(to: sentinel, atomically: true, encoding: .utf8)

        XCTAssertThrowsError(try AcquisitionWizard().run(outputCase: outputCase)) { error in
            guard case .caseAlreadyExists(let rejectedURL) = error as? RootstockBlueError else {
                return XCTFail("Expected an existing-case error, got \(error)")
            }
            XCTAssertEqual(rejectedURL, outputCase)
        }
        XCTAssertEqual(try String(contentsOf: sentinel, encoding: .utf8), "preserve this case")
    }

    func testAcquisitionWizardCleansStagedCaseWhenSourceIsRejected() throws {
        let source = try temporaryDirectory(prefix: "rsb-wizard-symlink-source")
        let outputCase = FileManager.default.temporaryDirectory
            .appendingPathComponent("rsb-wizard-rejected-\(UUID().uuidString).rsbcase")
        defer {
            try? FileManager.default.removeItem(at: source)
            try? FileManager.default.removeItem(at: outputCase)
        }
        try "fixture".write(
            to: source.appendingPathComponent("evidence.txt"),
            atomically: true,
            encoding: .utf8
        )
        try FileManager.default.createSymbolicLink(
            at: source.appendingPathComponent("linked-evidence.txt"),
            withDestinationURL: source.appendingPathComponent("evidence.txt")
        )

        XCTAssertThrowsError(
            try AcquisitionWizard().run(outputCase: outputCase, sourceTree: source)
        ) { error in
            XCTAssertTrue(error.localizedDescription.contains("symbolic link"))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: outputCase.path))
        XCTAssertTrue(try stagingDirectories(near: outputCase).isEmpty)
    }

    func testAcquireWithoutSourceThrowsHonestError() {
        XCTAssertThrowsError(try LogicalAcquire.acquire(to: URL(fileURLWithPath: "/tmp/nope"))) { err in
            let msg = (err as? LocalizedError)?.errorDescription ?? "\(err)"
            XCTAssertTrue(msg.lowercased().contains("filevault") || msg.lowercased().contains("source"))
        }
    }

    func testUnlockFileVaultAlwaysFailsHonestly() {
        XCTAssertThrowsError(try LogicalAcquire.unlockFileVault(volumeUUID: "TEST", password: nil)) { err in
            let msg = (err as? LocalizedError)?.errorDescription ?? "\(err)"
            XCTAssertTrue(msg.lowercased().contains("credential") || msg.lowercased().contains("secrets"))
        }
        XCTAssertThrowsError(try LogicalAcquire.unlockFileVault(volumeUUID: "TEST", password: "x")) { err in
            let msg = (err as? LocalizedError)?.errorDescription ?? "\(err)"
            XCTAssertTrue(msg.lowercased().contains("filevault") || msg.lowercased().contains("scope"))
        }
    }

    private func temporaryDirectory(prefix: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(prefix)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func stagingDirectories(near destination: URL) throws -> [URL] {
        let prefix = ".\(destination.lastPathComponent).rootstock-staging-"
        return try FileManager.default.contentsOfDirectory(
            at: destination.deletingLastPathComponent(),
            includingPropertiesForKeys: nil
        ).filter { $0.lastPathComponent.hasPrefix(prefix) }
    }
}
