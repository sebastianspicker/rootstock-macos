import XCTest
@testable import RootstockCore
@testable import RootstockLab

extension LabActionTests {
    func testWave12LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave12-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            WeblocInetlocPlanLabAction(),
            MailRulesAutomationPlanLabAction(),
            UnifiedLogObservationPlanLabAction(),
            DockPersistencePlanLabAction(),
            OsascriptScptPlanLabAction(),
            NetworkShareMountPlanLabAction()
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true)
            )
            XCTAssertTrue(plan.dryRun, "\(id) plan dryRun")
            XCTAssertTrue(plan.success, "\(id) plan success")
            XCTAssertFalse(plan.plannedSteps.isEmpty, "\(id) steps")

            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success, "\(id) install")
            XCTAssertFalse(install.artifacts.isEmpty, "\(id) artifacts")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a), "\(id) wrote \(a)")
                XCTAssertTrue(a.hasPrefix(root.path), "\(id) under lab root")
            }

            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(remove.success, "\(id) remove")
            for a in install.artifacts {
                XCTAssertFalse(FileManager.default.fileExists(atPath: a), "\(id) cleaned \(a)")
            }
        }
    }

    func testWave11LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            URLSchemeHandlerPlanLabAction(),
            LaunchdOverrideDepthPlanLabAction(),
            BrowserExtensionDualUsePlanLabAction(),
            ShortcutsAppIntentsPlanLabAction(),
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

    func testWave11LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave11-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            URLSchemeHandlerPlanLabAction(),
            LaunchdOverrideDepthPlanLabAction(),
            BrowserExtensionDualUsePlanLabAction(),
            ShortcutsAppIntentsPlanLabAction(),
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true)
            )
            XCTAssertTrue(plan.dryRun, "\(id) plan dryRun")
            XCTAssertTrue(plan.success, "\(id) plan success")
            XCTAssertFalse(plan.plannedSteps.isEmpty, "\(id) steps")
            let planBlob = (plan.message + plan.plannedSteps.joined()).lowercased()
            XCTAssertFalse(planBlob.contains("password="), "\(id) no secrets")
            XCTAssertFalse(planBlob.contains("disable santa now"), "\(id) no disable")
            XCTAssertFalse(planBlob.contains("run shortcuts payload"), "\(id) no run shortcuts")

            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success, "\(id) install")
            XCTAssertFalse(install.artifacts.isEmpty, "\(id) artifacts")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a), "\(id) wrote \(a)")
                XCTAssertTrue(a.hasPrefix(root.path), "\(id) under lab root")
            }

            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(remove.success, "\(id) remove")
            for a in install.artifacts {
                XCTAssertFalse(FileManager.default.fileExists(atPath: a), "\(id) cleaned \(a)")
            }
        }
    }

    func testLabPathsResolveLabRootDefaultAndOverride() {
        let def = LabPaths.resolveLabRoot(params: [:])
        XCTAssertTrue(def.path.hasSuffix("/Library/RootstockLab") || def.path.contains("Library/RootstockLab"))
        let cron = LabPaths.resolveLabRoot(params: [:], subdirectory: "cron")
        XCTAssertTrue(cron.path.hasSuffix("/Library/RootstockLab/cron") || cron.path.contains("RootstockLab/cron"))
        let custom = LabPaths.resolveLabRoot(params: ["labRoot": "/tmp/rootstock-lab-test-root"])
        XCTAssertEqual(custom.standardizedFileURL.path, "/tmp/rootstock-lab-test-root")
        // Explicit labRoot ignores default subdirectory
        let customWithSub = LabPaths.resolveLabRoot(
            params: ["labRoot": "/tmp/rootstock-lab-test-root"],
            subdirectory: "cron"
        )
        XCTAssertEqual(customWithSub.standardizedFileURL.path, "/tmp/rootstock-lab-test-root")
    }

    func testLabPathsSanitizeAndJsonStringList() {
        XCTAssertEqual(LabPaths.sanitizePathComponent("Hello World!"), "Hello_World_")
        XCTAssertEqual(LabPaths.sanitizePathComponent(""), "generic")
        XCTAssertEqual(LabPaths.jsonStringList(fromCSV: "OPEN, EXEC ,WRITE"), "\"OPEN\",\"EXEC\",\"WRITE\"")
    }

    func testLabMarkerLifecycleWriteStatusRemoveDrivesShippedHelpers() throws {
        let dir = try tempDir(prefix: "lifecycle")
        defer { try? FileManager.default.removeItem(at: dir) }
        let marker = dir.appendingPathComponent("shared.marker"); XCTAssertFalse(LabMarkerLifecycle.markerExists(at: marker))

        let copy = FileMarkerCopy(
            plan: FileMarkerPlanCopy(message: "plan \(marker.path)", steps: ["step-a"], cleanup: ["cleanup-a"]),
            apply: FileMarkerApplyCopy(dryRunMessage: "dry \(marker.path)", successMessage: "wrote \(marker.path)", steps: ["write"], cleanup: ["delete"]),
            status: FileMarkerStatusCopy(presentMessage: "present", absentMessage: "absent"),
            remove: FileMarkerRemoveCopy(
                dryRunMessage: { exists in "dry-remove exists=\(exists)" },
                successMessage: { exists in "removed exists=\(exists)" },
                cleanup: ["done"]
            )
        )

        let plan = try LabMarkerLifecycle.runFileMarker(FileMarkerLifecycleRequest(actionId: "lab.test.shared", operation: .plan, markerURL: marker, body: "hello", contextDryRun: true, copy: copy))
        XCTAssertTrue(plan.success); XCTAssertTrue(plan.dryRun)
        XCTAssertFalse(LabMarkerLifecycle.markerExists(at: marker))

        let dryInstall = try LabMarkerLifecycle.runFileMarker(FileMarkerLifecycleRequest(actionId: "lab.test.shared", operation: .install, markerURL: marker, body: "hello", contextDryRun: true, copy: copy))
        XCTAssertTrue(dryInstall.dryRun); XCTAssertFalse(LabMarkerLifecycle.markerExists(at: marker))

        let install = try LabMarkerLifecycle.runFileMarker(FileMarkerLifecycleRequest(actionId: "lab.test.shared", operation: .install, markerURL: marker, body: "hello-body", contextDryRun: false, copy: copy))
        XCTAssertTrue(install.success); XCTAssertFalse(install.dryRun)
        XCTAssertTrue(LabMarkerLifecycle.markerExists(at: marker)); XCTAssertEqual(try String(contentsOf: marker, encoding: .utf8), "hello-body")

        let status = try LabMarkerLifecycle.runFileMarker(FileMarkerLifecycleRequest(actionId: "lab.test.shared", operation: .status, markerURL: marker, body: "hello-body", contextDryRun: false, copy: copy))
        XCTAssertEqual(status.message, "present")

        let remove = try LabMarkerLifecycle.runFileMarker(FileMarkerLifecycleRequest(actionId: "lab.test.shared", operation: .remove, markerURL: marker, body: "hello-body", contextDryRun: false, copy: copy))
        XCTAssertTrue(remove.success); XCTAssertFalse(LabMarkerLifecycle.markerExists(at: marker))
    }

    func testClickFixPlanActionUsesSharedLifecycle() async throws {
        let dir = try tempDir(prefix: "clickfix-shared")
        defer { try? FileManager.default.removeItem(at: dir) }
        let action = ClickFixTerminalPlanLabAction()
        let params = ["labRoot": dir.path]
        let plan = try await action.run(
            request: LabActionRequest(
                actionId: ClickFixTerminalPlanLabAction.id,
                operation: .plan,
                parameters: params
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.success)
        XCTAssertTrue(plan.dryRun)
        XCTAssertFalse(plan.plannedSteps.isEmpty)

        let install = try await action.run(
            request: LabActionRequest(
                actionId: ClickFixTerminalPlanLabAction.id,
                operation: .install,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.artifacts.isEmpty)
        for a in install.artifacts {
            XCTAssertTrue(FileManager.default.fileExists(atPath: a), a)
        }
        // Public resolveLabRoot is the shared LabPaths implementation
        let resolved = ClickFixTerminalPlanLabAction.resolveLabRoot(params: params)
        XCTAssertEqual(resolved.standardizedFileURL.path, dir.standardizedFileURL.path)
    }

}
