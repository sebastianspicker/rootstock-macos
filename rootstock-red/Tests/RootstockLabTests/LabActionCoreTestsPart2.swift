import XCTest
@testable import RootstockCore
@testable import RootstockLab

extension LabActionTests {
    func testLoginItemMarkerPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "loginitem-rw")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = [
            "labRoot": root.path,
            "label": "com.rootstock.red.lab.loginitem.test",
        ]
        let action = LoginItemMarkerLabAction()

        let plan = try await action.run( request: LabActionRequest( actionId: LoginItemMarkerLabAction.id, operation: .plan, parameters: params ), context: labContext(dryRun: true) )
        XCTAssertTrue(plan.success); XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.persist.loginitem_marker"); XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertFalse(plan.cleanupNotes.isEmpty)
        XCTAssertTrue( plan.cleanupNotes.contains { $0.localizedCaseInsensitiveContains("BTM") } || plan.message.localizedCaseInsensitiveContains("BTM") )

        let install = try await action.run( request: LabActionRequest( actionId: LoginItemMarkerLabAction.id, operation: .install, parameters: params ), context: labContext(dryRun: false) )
        XCTAssertTrue(install.success); XCTAssertFalse(install.artifacts.isEmpty)
        for path in install.artifacts {
            XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        }

        let status = try await action.run( request: LabActionRequest( actionId: LoginItemMarkerLabAction.id, operation: .status, parameters: params ), context: labContext(dryRun: false) )
        XCTAssertTrue(status.message.contains("present"))

        let remove = try await action.run( request: LabActionRequest( actionId: LoginItemMarkerLabAction.id, operation: .remove, parameters: params ), context: labContext(dryRun: false) )
        XCTAssertTrue(remove.success)
        for path in install.artifacts {
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
    }

    func testAtomicIOCPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "atomic-ioc")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path, "technique": "T1543.001"]
        let action = AtomicIOCLabAction()
        let marker = root
            .appendingPathComponent("purple-ioc")
            .appendingPathComponent(AtomicIOCLabAction.markerName)

        let plan = try await action.run(
            request: LabActionRequest(
                actionId: AtomicIOCLabAction.id,
                operation: .plan,
                parameters: params
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.purple.atomic_ioc")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertFalse(plan.cleanupNotes.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))

        let install = try await action.run(
            request: LabActionRequest(
                actionId: AtomicIOCLabAction.id,
                operation: .install,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
        let body = try String(contentsOf: marker, encoding: .utf8)
        XCTAssertTrue(body.contains("T1543.001") || body.contains("atomic"))

        let remove = try await action.run(
            request: LabActionRequest(
                actionId: AtomicIOCLabAction.id,
                operation: .remove,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    func testXPCHelperPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "xpc-plan")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path, "helper": "com.example.helper"]
        let action = XPCHelperPlanLabAction()
        let marker = XPCHelperPlanLabAction.markerURL(labRoot: root, helper: "com.example.helper")

        let plan = try await action.run(
            request: LabActionRequest(
                actionId: XPCHelperPlanLabAction.id,
                operation: .plan,
                parameters: params
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.success)
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.surface.xpc_helper_plan")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertFalse(plan.cleanupNotes.isEmpty)
        XCTAssertTrue(
            plan.message.contains("PrivilegedHelperTools")
                || plan.plannedSteps.contains { $0.contains("PrivilegedHelperTools") }
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))

        let install = try await action.run(
            request: LabActionRequest(
                actionId: XPCHelperPlanLabAction.id,
                operation: .install,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
        // Must not write system helper path
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: "/Library/PrivilegedHelperTools/com.example.helper"
            )
        )

        let remove = try await action.run(
            request: LabActionRequest(
                actionId: XPCHelperPlanLabAction.id,
                operation: .remove,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    func testSOTA2026LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            LoginItemMarkerLabAction(),
            AtomicIOCLabAction(),
            XPCHelperPlanLabAction(),
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: type(of: action).id,
                        operation: .plan,
                        parameters: ["labRoot": "/tmp"]
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

    func testShellRCDryRunPlanDoesNotWrite() async throws {
        let dir = try tempDir(prefix: "shellrc-dry")
        defer { try? FileManager.default.removeItem(at: dir) }
        let rc = dir.appendingPathComponent(".zshrc_lab")

        let action = ShellRCLabAction()
        let result = try await action.run(
            request: LabActionRequest(
                actionId: ShellRCLabAction.id,
                operation: .plan,
                parameters: ["rcFile": rc.path]
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(result.success)
        XCTAssertTrue(result.dryRun)
        XCTAssertEqual(result.actionId, "lab.persist.shellrc")
        XCTAssertFalse(result.plannedSteps.isEmpty)
        XCTAssertFalse(result.cleanupNotes.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: rc.path))
    }

    func testShellRCInstallStatusRemoveLifecycle() async throws {
        let dir = try tempDir(prefix: "shellrc-rw")
        defer { try? FileManager.default.removeItem(at: dir) }
        let rc = dir.appendingPathComponent(".zshrc_lab")
        try "export PATH=/usr/bin\n".write(to: rc, atomically: true, encoding: .utf8)

        let params = ["rcFile": rc.path]
        let action = ShellRCLabAction()
        let ctx = labContext(dryRun: false)

        let install = try await action.run(
            request: LabActionRequest(actionId: ShellRCLabAction.id, operation: .install, parameters: params),
            context: ctx
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.dryRun)
        let body = try String(contentsOf: rc, encoding: .utf8)
        XCTAssertTrue(body.contains(ShellRCLabAction.markerPrefix))
        XCTAssertTrue(body.contains("export PATH=/usr/bin"))

        let status = try await action.run(
            request: LabActionRequest(actionId: ShellRCLabAction.id, operation: .status, parameters: params),
            context: ctx
        )
        XCTAssertTrue(status.message.contains("present"))

        let remove = try await action.run(
            request: LabActionRequest(actionId: ShellRCLabAction.id, operation: .remove, parameters: params),
            context: ctx
        )
        XCTAssertTrue(remove.success)
        let after = try String(contentsOf: rc, encoding: .utf8)
        XCTAssertFalse(after.contains(ShellRCLabAction.markerPrefix))
        XCTAssertTrue(after.contains("export PATH=/usr/bin"))
    }

    func testCronMarkerPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "cron-rw")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let action = CronMarkerLabAction()
        let marker = CronMarkerLabAction.markerURL(labRoot: root)

        let plan = try await action.run(
            request: LabActionRequest(actionId: CronMarkerLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.persist.cron_marker")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertTrue(plan.message.localizedCaseInsensitiveContains("crontab") || plan.cleanupNotes.contains { $0.localizedCaseInsensitiveContains("crontab") })
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))

        let install = try await action.run(
            request: LabActionRequest(actionId: CronMarkerLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))

        let status = try await action.run(
            request: LabActionRequest(actionId: CronMarkerLabAction.id, operation: .status, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(status.message.contains("present"))

        let remove = try await action.run(
            request: LabActionRequest(actionId: CronMarkerLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }
}
