import XCTest
@testable import RootstockCore
@testable import RootstockLab

extension LabActionTests {
    func testDyldEnvPlanDryRunAndLifecycle() async throws {
        let root = try tempDir(prefix: "dyld-rw")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path, "app": "SampleApp"]
        let action = DyldEnvLabAction()
        let marker = DyldEnvLabAction.markerURL(labRoot: root, app: "SampleApp")

        let plan = try await action.run(
            request: LabActionRequest(actionId: DyldEnvLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.success)
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.surface.dyld_env")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertFalse(plan.cleanupNotes.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))

        let install = try await action.run(
            request: LabActionRequest(actionId: DyldEnvLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
        let body = try String(contentsOf: marker, encoding: .utf8)
        XCTAssertTrue(body.contains("DYLD_") || body.contains("ROOTSTOCK_RED_LAB_DYLD_MARKER"))

        let remove = try await action.run(
            request: LabActionRequest(actionId: DyldEnvLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    func testNewLabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            ShellRCLabAction(),
            CronMarkerLabAction(),
            DyldEnvLabAction(),
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: type(of: action).id,
                        operation: .plan,
                        parameters: ["labRoot": "/tmp", "rcFile": "/tmp/x"]
                    ),
                    context: bad
                )
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized for \(type(of: action).id), got \(error)")
                    return
                }
            } catch {
                XCTFail("unexpected error for \(type(of: action).id): \(error)")
            }
        }
    }

    func testPlanAllDryRunsBothWithoutWrites() async throws {
        let laDir = try tempDir(prefix: "plan-la")
        let dylibRoot = try tempDir(prefix: "plan-dylib")
        defer {
            try? FileManager.default.removeItem(at: laDir)
            try? FileManager.default.removeItem(at: dylibRoot)
        }

        // planAll uses action defaults; ensure no accidental home writes by using
        // a custom registry of only the two lab actions exercised via direct plan.
        let pipeline = LabPipeline(registry: ActionRegistry(actions: [
            LaunchAgentLabAction(),
            DylibSurfaceLabAction(),
        ]))

        // Direct plan with temp paths
        let la = try await LaunchAgentLabAction().run(
            request: LabActionRequest(
                actionId: LaunchAgentLabAction.id,
                operation: .plan,
                parameters: ["directory": laDir.path, "label": "com.rootstock.red.lab.plan"]
            ),
            context: labContext(dryRun: true)
        )
        let dy = try await DylibSurfaceLabAction().run(
            request: LabActionRequest(
                actionId: DylibSurfaceLabAction.id,
                operation: .plan,
                parameters: ["labRoot": dylibRoot.path]
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(la.dryRun)
        XCTAssertTrue(dy.dryRun)
        XCTAssertTrue(laDir.isEmptyDirectory)
        XCTAssertTrue(dylibRoot.isEmptyDirectory)

        // planAll with noop-free registry still requires consent; defaults only plan paths under home,
        // we assert structure/serialization only with production planAll (dry-run messages, no force apply).
        let all = try await pipeline.planAll(context: labContext(dryRun: true))
        XCTAssertEqual(all.count, 2)
        XCTAssertTrue(all.allSatisfy(\.dryRun))
        XCTAssertTrue(all.allSatisfy(\.success))

        let encoded = try JSONEncoder().encode(LabPlanAllResult(results: all))
        XCTAssertFalse(encoded.isEmpty)
        let decoded = try JSONDecoder().decode(LabPlanAllResult.self, from: encoded)
        XCTAssertEqual(decoded.results.count, 2)
    }

    func testConsentRequired() async {
        let action = LaunchAgentLabAction()
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        do {
            _ = try await action.run(
                request: LabActionRequest(
                    actionId: LaunchAgentLabAction.id,
                    operation: .status,
                    parameters: ["directory": "/tmp", "label": "com.rootstock.red.lab.x"]
                ),
                context: bad
            )
            XCTFail("expected unauthorized")
        } catch let error as RootstockError {
            guard case .unauthorized = error else {
                XCTFail("expected unauthorized, got \(error)")
                return
            }
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func testActionResultCodableIncludesNewFields() throws {
        let result = ActionResult(
            actionId: "lab.persist.launchagent",
            success: true,
            message: "ok",
            dryRun: true,
            plannedSteps: ["a"],
            cleanupNotes: ["b"],
            artifacts: ["/tmp/x"]
        )
        let data = try JSONEncoder().encode(result)
        let decoded = try JSONDecoder().decode(ActionResult.self, from: data)
        XCTAssertEqual(decoded, result)

        // Missing optional keys still decode
        let legacy = """
        {"actionId":"lab.noop","success":true,"message":"m","dryRun":true}
        """.data(using: .utf8)!
        let legacyDecoded = try JSONDecoder().decode(ActionResult.self, from: legacy)
        XCTAssertEqual(legacyDecoded.plannedSteps, [])
        XCTAssertEqual(legacyDecoded.cleanupNotes, [])
        XCTAssertEqual(legacyDecoded.artifacts, [])
    }

    func testPipelineRejectsUnknownAction() async {
        let pipeline = LabPipeline()
        do {
            _ = try await pipeline.run(
                request: LabActionRequest(actionId: "lab.evil", operation: .plan),
                context: labContext(dryRun: true)
            )
            XCTFail("expected invalidArgument")
        } catch let error as RootstockError {
            guard case .invalidArgument = error else {
                XCTFail("expected invalidArgument")
                return
            }
        } catch {
            XCTFail("unexpected \(error)")
        }
    }
}
