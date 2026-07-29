import XCTest
@testable import RootstockCore
@testable import RootstockLab

final class LabActionTests: XCTestCase {
    func labContext(dryRun: Bool) -> EvaluationContext {
        EvaluationContext(
            mode: .lab,
            profile: .standard,
            dryRun: dryRun,
            consent: ConsentTokens(
                iAmAuthorized: true,
                scope: "ENG",
                operatorName: "alice"
            )
        )
    }

    func tempDir(prefix: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-red-lab-\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    func testLaunchAgentDryRunInstallDoesNotWrite() async throws {
        let dir = try tempDir(prefix: "la-dry")
        defer { try? FileManager.default.removeItem(at: dir) }

        let action = LaunchAgentLabAction()
        let request = LabActionRequest(
            actionId: LaunchAgentLabAction.id,
            operation: .install,
            parameters: [
                "directory": dir.path,
                "label": "com.rootstock.red.lab.test",
            ]
        )
        let result = try await action.run(request: request, context: labContext(dryRun: true))

        XCTAssertTrue(result.success)
        XCTAssertTrue(result.dryRun)
        XCTAssertEqual(result.actionId, "lab.persist.launchagent")
        XCTAssertFalse(result.plannedSteps.isEmpty)
        XCTAssertTrue(result.message.contains("BTM") || result.cleanupNotes.contains { $0.contains("BTM") })
        XCTAssertFalse(result.artifacts.isEmpty)

        let plist = dir.appendingPathComponent("com.rootstock.red.lab.test.plist")
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: plist.path),
            "dry-run must not write LaunchAgent plist"
        )
    }

    func testLaunchAgentInstallStatusRemoveWithTempDirectory() async throws {
        let dir = try tempDir(prefix: "la-rw")
        defer { try? FileManager.default.removeItem(at: dir) }

        let label = "com.rootstock.red.lab.lifecycle"
        let params = ["directory": dir.path, "label": label]
        let action = LaunchAgentLabAction()
        let ctx = labContext(dryRun: false)
        let pipeline = LabPipeline(registry: .production())

        let install = try await pipeline.run(
            request: LabActionRequest(
                actionId: LaunchAgentLabAction.id,
                operation: .install,
                parameters: params
            ),
            context: ctx
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.dryRun)
        XCTAssertFalse(install.cleanupNotes.isEmpty)

        let plist = dir.appendingPathComponent("\(label).plist")
        XCTAssertTrue(FileManager.default.fileExists(atPath: plist.path))

        // Harmless ProgramArguments
        let dict = NSDictionary(contentsOf: plist) as? [String: Any]
        XCTAssertEqual(dict?["Label"] as? String, label)
        let args = dict?["ProgramArguments"] as? [String]
        XCTAssertEqual(args?.first, "/usr/bin/true")

        let status = try await action.run(
            request: LabActionRequest(
                actionId: LaunchAgentLabAction.id,
                operation: .status,
                parameters: params
            ),
            context: ctx
        )
        XCTAssertTrue(status.success)
        XCTAssertTrue(status.message.contains("present"))
        XCTAssertEqual(status.artifacts, [plist.path])

        let remove = try await action.run(
            request: LabActionRequest(
                actionId: LaunchAgentLabAction.id,
                operation: .remove,
                parameters: params
            ),
            context: ctx
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: plist.path))
        XCTAssertTrue(remove.cleanupNotes.contains { $0.contains("BTM") })
    }

    func testLaunchAgentRejectsPathTraversalLabel() async throws {
        let dir = try tempDir(prefix: "la-trav")
        defer { try? FileManager.default.removeItem(at: dir) }

        let action = LaunchAgentLabAction()
        let maliciousLabels = [
            "../../.ssh/orchard_pwn",
            "../escape",
            "com/rootstock-red/lab/bad",
            "com.rootstock.red.lab/../../tmp/pwn",
            "..",
            "foo/bar",
        ]

        for bad in maliciousLabels {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: LaunchAgentLabAction.id,
                        operation: .install,
                        parameters: [
                            "directory": dir.path,
                            "label": bad,
                        ]
                    ),
                    context: labContext(dryRun: false)
                )
                XCTFail("expected invalidArgument for label \(bad)")
            } catch let error as RootstockError {
                guard case .invalidArgument = error else {
                    XCTFail("unexpected RootstockError for \(bad): \(error)")
                    continue
                }
            } catch {
                XCTFail("unexpected error type for \(bad): \(error)")
            }
        }

        // No plists written under or outside temp dir from traversal attempts
        let contents = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        XCTAssertTrue(contents.isEmpty, "traversal must not create files; saw \(contents)")

        // Explicit path containment: resolvePlistURL rejects escape even if sanitize missed
        XCTAssertThrowsError(
            try LaunchAgentLabAction.resolveLabel(params: ["label": "../../.ssh/orchard_pwn"])
        )
        let safe = try LaunchAgentLabAction.resolveLabel(params: ["label": "com.rootstock.red.lab.safe"])
        XCTAssertEqual(safe, "com.rootstock.red.lab.safe")
        let url = try LaunchAgentLabAction.resolvePlistURL(directory: dir, label: safe)
        XCTAssertTrue(url.path.hasPrefix(dir.standardizedFileURL.path + "/"))
        XCTAssertEqual(url.lastPathComponent, "com.rootstock.red.lab.safe.plist")
    }

    func testLaunchAgentPathTraversalDoesNotWriteOutsideDirectory() async throws {
        // Skeptic demo: --label '../../.ssh/orchard_pwn' must not write ~/.ssh/orchard_pwn.plist
        let homeSSH = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh", isDirectory: true)
        let escapeTarget = homeSSH.appendingPathComponent("orchard_pwn.plist")
        let existedBefore = FileManager.default.fileExists(atPath: escapeTarget.path)

        let dir = try tempDir(prefix: "la-outside")
        defer { try? FileManager.default.removeItem(at: dir) }

        let action = LaunchAgentLabAction()
        do {
            _ = try await action.run(
                request: LabActionRequest(
                    actionId: LaunchAgentLabAction.id,
                    operation: .install,
                    parameters: [
                        "directory": dir.path,
                        "label": "../../.ssh/orchard_pwn",
                    ]
                ),
                context: labContext(dryRun: false)
            )
            XCTFail("path traversal label must fail")
        } catch is RootstockError {
            // expected
        }

        let existsAfter = FileManager.default.fileExists(atPath: escapeTarget.path)
        if !existedBefore {
            XCTAssertFalse(existsAfter, "must not create \(escapeTarget.path)")
        }
    }

    func testLaunchAgentRemoveDryRunDoesNotDelete() async throws {
        let dir = try tempDir(prefix: "la-rm-dry")
        defer { try? FileManager.default.removeItem(at: dir) }

        let label = "com.rootstock.red.lab.keep"
        let plist = dir.appendingPathComponent("\(label).plist")
        try Data("<plist></plist>".utf8).write(to: plist)

        let action = LaunchAgentLabAction()
        let result = try await action.run(
            request: LabActionRequest(
                actionId: LaunchAgentLabAction.id,
                operation: .remove,
                parameters: ["directory": dir.path, "label": label]
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(result.dryRun)
        XCTAssertTrue(FileManager.default.fileExists(atPath: plist.path))
    }

    func testDylibPlanDryRunDoesNotWrite() async throws {
        let root = try tempDir(prefix: "dylib-dry")
        defer { try? FileManager.default.removeItem(at: root) }

        let action = DylibSurfaceLabAction()
        let result = try await action.run(
            request: LabActionRequest(
                actionId: DylibSurfaceLabAction.id,
                operation: .plan,
                parameters: ["labRoot": root.path, "app": "SampleApp"]
            ),
            context: labContext(dryRun: true)
        )

        XCTAssertTrue(result.success)
        XCTAssertTrue(result.dryRun)
        XCTAssertEqual(result.actionId, "lab.surface.dylib_plan")
        XCTAssertFalse(result.plannedSteps.isEmpty)
        XCTAssertTrue(result.message.contains("marker") || result.message.contains("plan"))

        let marker = DylibSurfaceLabAction.markerURL(labRoot: root, app: "SampleApp")
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    func testDylibApplyStatusRemoveLifecycle() async throws {
        let root = try tempDir(prefix: "dylib-rw")
        defer { try? FileManager.default.removeItem(at: root) }

        let params = ["labRoot": root.path, "app": "TestApp"]
        let action = DylibSurfaceLabAction()
        let ctx = labContext(dryRun: false)
        let marker = DylibSurfaceLabAction.markerURL(labRoot: root, app: "TestApp")

        let apply = try await action.run(
            request: LabActionRequest(
                actionId: DylibSurfaceLabAction.id,
                operation: .install,
                parameters: params
            ),
            context: ctx
        )
        XCTAssertTrue(apply.success)
        XCTAssertFalse(apply.dryRun)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
        // Empty marker, not a dylib
        let size = try FileManager.default.attributesOfItem(atPath: marker.path)[.size] as? NSNumber
        XCTAssertEqual(size?.intValue, 0)

        let status = try await action.run(
            request: LabActionRequest(
                actionId: DylibSurfaceLabAction.id,
                operation: .status,
                parameters: params
            ),
            context: ctx
        )
        XCTAssertTrue(status.message.contains("present"))

        let remove = try await action.run(
            request: LabActionRequest(
                actionId: DylibSurfaceLabAction.id,
                operation: .remove,
                parameters: params
            ),
            context: ctx
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }
}
