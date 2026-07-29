import XCTest
@testable import RootstockCore
@testable import RootstockLab

extension LabActionTests {
    func testPeriodicMarkerPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "periodic-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let action = PeriodicMarkerLabAction()
        let plan = try await action.run(
            request: LabActionRequest(actionId: PeriodicMarkerLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.persist.periodic_marker")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertFalse(plan.cleanupNotes.isEmpty)
        let install = try await action.run(
            request: LabActionRequest(actionId: PeriodicMarkerLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.artifacts.isEmpty)
        for a in install.artifacts { XCTAssertTrue(FileManager.default.fileExists(atPath: a)) }
        let remove = try await action.run(
            request: LabActionRequest(actionId: PeriodicMarkerLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
    }

    func testSudoersPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "sudoers-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let action = SudoersPlanLabAction()
        let plan = try await action.run(
            request: LabActionRequest(actionId: SudoersPlanLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.surface.sudoers_plan")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertTrue(plan.message.contains("sudoers") || plan.plannedSteps.contains { $0.contains("sudoers") })
        let install = try await action.run(
            request: LabActionRequest(actionId: SudoersPlanLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: "/etc/sudoers.d/rootstock-red-lab"))
        let remove = try await action.run(
            request: LabActionRequest(actionId: SudoersPlanLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
    }

    func testESFExpectPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "esf-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path, "technique": "T1543.001", "esfEvents": "OPEN,WRITE,CREATE"]
        let action = ESFExpectLabAction()
        let plan = try await action.run(
            request: LabActionRequest(actionId: ESFExpectLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.purple.esf_expect")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        let install = try await action.run(
            request: LabActionRequest(actionId: ESFExpectLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.artifacts.isEmpty)
        let body = try String(contentsOfFile: install.artifacts[0], encoding: .utf8)
        XCTAssertTrue(body.contains("T1543.001"))
        XCTAssertTrue(body.contains("OPEN") || body.contains("esfExpected"))
        let remove = try await action.run(
            request: LabActionRequest(actionId: ESFExpectLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
    }

    func testQuarantinePlanLifecycle() async throws {
        let root = try tempDir(prefix: "q-plan")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let action = QuarantinePlanLabAction()
        let plan = try await action.run(
            request: LabActionRequest(actionId: QuarantinePlanLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.surface.quarantine_plan")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertFalse(plan.cleanupNotes.isEmpty)
        let install = try await action.run(
            request: LabActionRequest(actionId: QuarantinePlanLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.artifacts.isEmpty)
        for a in install.artifacts { XCTAssertTrue(FileManager.default.fileExists(atPath: a)) }
        let remove = try await action.run(
            request: LabActionRequest(actionId: QuarantinePlanLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
    }

    func testKeychainPathPlanLifecycle() async throws {
        let root = try tempDir(prefix: "kc-plan")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let action = KeychainPathPlanLabAction()
        let plan = try await action.run(
            request: LabActionRequest(actionId: KeychainPathPlanLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.surface.keychain_path_plan")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        let blob = (plan.message + plan.plannedSteps.joined() + plan.cleanupNotes.joined()).lowercased()
        XCTAssertFalse(blob.contains("password="))
        let install = try await action.run(
            request: LabActionRequest(actionId: KeychainPathPlanLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        let remove = try await action.run(
            request: LabActionRequest(actionId: KeychainPathPlanLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
    }

    func testXattrDetectPairLifecycle() async throws {
        let root = try tempDir(prefix: "xattr-pair")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path, "technique": "T1553.001"]
        let action = XattrDetectPairLabAction()
        let plan = try await action.run(
            request: LabActionRequest(actionId: XattrDetectPairLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.purple.xattr_detect_pair")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        let install = try await action.run(
            request: LabActionRequest(actionId: XattrDetectPairLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.artifacts.isEmpty)
        let body = try String(contentsOfFile: install.artifacts[0], encoding: .utf8)
        XCTAssertTrue(body.contains("T1553.001") || body.contains("xattr") || body.contains("quarantine") || body.contains("OPEN"))
        let remove = try await action.run(
            request: LabActionRequest(actionId: XattrDetectPairLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
    }

    func testWave5LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            ESFSensorPlanLabAction(),
            TCCGraphPlanLabAction(),
            PatchDebtPlanLabAction(),
            LaunchConstraintPlanLabAction(),
            LOLMultistagePlanLabAction(),
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

    func testWave5LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave5-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            ESFSensorPlanLabAction(),
            TCCGraphPlanLabAction(),
            PatchDebtPlanLabAction(),
            LaunchConstraintPlanLabAction(),
            LOLMultistagePlanLabAction(),
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
                XCTAssertFalse(a.contains("/Library/PrivilegedHelperTools"), "\(id) no system helper")
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

    func testWave6LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            NetworkExtensionPlanLabAction(),
            AuthRightsPlanLabAction(),
            DeveloperToolchainPlanLabAction(),
            TimeMachinePlanLabAction(),
            MobileconfigSideloadPlanLabAction(),
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

    func testWave6LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave6-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            NetworkExtensionPlanLabAction(),
            AuthRightsPlanLabAction(),
            DeveloperToolchainPlanLabAction(),
            TimeMachinePlanLabAction(),
            MobileconfigSideloadPlanLabAction(),
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
            // Safety: plan must not write system helpers / auth.db / NE config
            let planBlob = (plan.message + plan.plannedSteps.joined()).lowercased()
            XCTAssertFalse(planBlob.contains("password="), "\(id) no secrets")

            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success, "\(id) install")
            XCTAssertFalse(install.artifacts.isEmpty, "\(id) artifacts")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a), "\(id) wrote \(a)")
                XCTAssertFalse(a.contains("/Library/PrivilegedHelperTools"), "\(id) no system helper")
                XCTAssertFalse(a.contains("/var/db/auth.db"), "\(id) no auth.db write")
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
}
