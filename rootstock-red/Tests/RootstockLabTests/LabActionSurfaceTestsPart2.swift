import XCTest
@testable import RootstockCore
@testable import RootstockLab

extension LabActionTests {
    func testWave7LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            AppSandboxPlanLabAction(),
            NotarizationPlanLabAction(),
            VirtualizationPlanLabAction(),
            ContinuityAirDropPlanLabAction(),
            FileVaultEscrowPlanLabAction(),
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

    func testWave7LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave7-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            AppSandboxPlanLabAction(),
            NotarizationPlanLabAction(),
            VirtualizationPlanLabAction(),
            ContinuityAirDropPlanLabAction(),
            FileVaultEscrowPlanLabAction(),
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
            XCTAssertFalse(planBlob.contains("recovery key="), "\(id) no recovery keys")

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
                XCTAssertFalse(a.contains("FileVaultMaster"), "\(id) no FV master keychain write")
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

    func testWave8LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            ClickFixTerminalPlanLabAction(),
            RemoteAppleEventsPlanLabAction(),
            SpotlightAICachePlanLabAction(),
            SecurityMgmtPlanePlanLabAction(),
            ThirdPartyTCCInheritancePlanLabAction(),
            SSHAgentKeyPathPlanLabAction(),
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

    func testWave8LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave8-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            ClickFixTerminalPlanLabAction(),
            RemoteAppleEventsPlanLabAction(),
            SpotlightAICachePlanLabAction(),
            SecurityMgmtPlanePlanLabAction(),
            ThirdPartyTCCInheritancePlanLabAction(),
            SSHAgentKeyPathPlanLabAction(),
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
            XCTAssertFalse(planBlob.contains("begin rsa private key"), "\(id) no private keys")
            XCTAssertFalse(planBlob.contains("paste this payload"), "\(id) no ClickFix recipes")

            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success, "\(id) install")
            XCTAssertFalse(install.artifacts.isEmpty, "\(id) artifacts")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a), "\(id) wrote \(a)")
                XCTAssertFalse(a.contains("/Library/PrivilegedHelperTools"), "\(id) no system helper")
                XCTAssertFalse(a.contains("/.ssh/"), "\(id) no ssh key write")
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

    func testWave9LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            PackageKitInstallerPlanLabAction(),
            ArchiveQuarantinePlanLabAction(),
            InfoStealerPathPlanLabAction(),
            TCCESFVisibilityPlanLabAction(),
            MDMProfileParsePlanLabAction(),
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

    func testWave9LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave9-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            PackageKitInstallerPlanLabAction(),
            ArchiveQuarantinePlanLabAction(),
            InfoStealerPathPlanLabAction(),
            TCCESFVisibilityPlanLabAction(),
            MDMProfileParsePlanLabAction(),
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
            XCTAssertFalse(planBlob.contains("begin rsa private key"), "\(id) no private keys")
            XCTAssertFalse(planBlob.contains("strip quarantine now"), "\(id) no quarantine strip")
            XCTAssertFalse(planBlob.contains("select * from access"), "\(id) no TCC dump")

            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success, "\(id) install")
            XCTAssertFalse(install.artifacts.isEmpty, "\(id) artifacts")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a), "\(id) wrote \(a)")
                XCTAssertFalse(a.contains("/Library/PrivilegedHelperTools"), "\(id) no system helper")
                XCTAssertFalse(a.contains("/Library/Receipts"), "\(id) no system receipts")
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
