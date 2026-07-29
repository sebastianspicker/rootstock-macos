import XCTest
@testable import RootstockCore
@testable import RootstockLab

extension LabActionTests {
    func testWave16LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            AirplayReceiverSurfacePlanLabAction(),
            HandoffClipboardDepthPlanLabAction(),
            ImessagePathPlanePlanLabAction(),
            FacetimeCameraSurfacePlanLabAction(),
            FinderSyncExtensionPlanLabAction(),
            FileproviderDomainPlanLabAction(),
            NotificationCenterDepthPlanLabAction(),
            SiriSuggestionsPlanePlanLabAction(),
            SpotlightImporterDepthPlanLabAction(),
            ContactsPathPlanePlanLabAction(),
            CalendarServerPathPlanLabAction(),
            RemindersCloudPathPlanLabAction(),
            MapsLocationPathPlanLabAction(),
            WeatherWidgetPathPlanLabAction(),
            MusicLibraryPathPlanLabAction(),
            BooksPathPlanePlanLabAction(),
            PodcastsPathPlanePlanLabAction(),
            TvAppPathPlanePlanLabAction(),
            HomekitPathPlanePlanLabAction(),
            HealthPathPlanePlanLabAction(),
            WalletPassPathPlanLabAction(),
            FindmyPathPlanePlanLabAction(),
            ShortcutsIcloudSyncPlanLabAction(),
            DevicemanagementProfilePlanLabAction(),
            SoftwareupdateCatalogPlanLabAction()
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(actionId: type(of: action).id, operation: .plan, parameters: ["labRoot": "/tmp"]),
                    context: bad)
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else { XCTFail("expected unauthorized"); return }
            } catch { XCTFail("unexpected \(error)") }
        }
    }

    func testWave16LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave16-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [ AirplayReceiverSurfacePlanLabAction(), HandoffClipboardDepthPlanLabAction(), ImessagePathPlanePlanLabAction(), FacetimeCameraSurfacePlanLabAction(), FinderSyncExtensionPlanLabAction(), FileproviderDomainPlanLabAction(), NotificationCenterDepthPlanLabAction(), SiriSuggestionsPlanePlanLabAction(), SpotlightImporterDepthPlanLabAction(), ContactsPathPlanePlanLabAction(), CalendarServerPathPlanLabAction(), RemindersCloudPathPlanLabAction(), MapsLocationPathPlanLabAction(), WeatherWidgetPathPlanLabAction(), MusicLibraryPathPlanLabAction(), BooksPathPlanePlanLabAction(), PodcastsPathPlanePlanLabAction(), TvAppPathPlanePlanLabAction(), HomekitPathPlanePlanLabAction(), HealthPathPlanePlanLabAction(), WalletPassPathPlanLabAction(), FindmyPathPlanePlanLabAction(), ShortcutsIcloudSyncPlanLabAction(), DevicemanagementProfilePlanLabAction(), SoftwareupdateCatalogPlanLabAction() ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true))
            XCTAssertTrue(plan.dryRun && plan.success, "\(id)")
            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false))
            XCTAssertTrue(install.success && !install.artifacts.isEmpty, "\(id)")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a) && a.hasPrefix(root.path))
            }
            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false))
            XCTAssertTrue(remove.success)
            for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
        }
    }

    func testWave15LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            PhotosLibraryPathPlanLabAction(),
            VpnConfigDualusePlanLabAction(),
            SandboxContainerDepthPlanLabAction(),
            XpcMachServiceDepthPlanLabAction(),
            TmLocalSnapshotDepthPlanLabAction(),
            EmondLegacyDepthPlanLabAction(),
            ScreenSharingArdDepthPlanLabAction(),
            KeychainAclPathPlanLabAction(),
            PythonRuntimeDualusePlanLabAction(),
            ShellPluginManagerPlanLabAction()
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(actionId: type(of: action).id, operation: .plan, parameters: ["labRoot": "/tmp"]),
                    context: bad)
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else { XCTFail("expected unauthorized"); return }
            } catch { XCTFail("unexpected \(error)") }
        }
    }

    func testWave15LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave15-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            PhotosLibraryPathPlanLabAction(),
            VpnConfigDualusePlanLabAction(),
            SandboxContainerDepthPlanLabAction(),
            XpcMachServiceDepthPlanLabAction(),
            TmLocalSnapshotDepthPlanLabAction(),
            EmondLegacyDepthPlanLabAction(),
            ScreenSharingArdDepthPlanLabAction(),
            KeychainAclPathPlanLabAction(),
            PythonRuntimeDualusePlanLabAction(),
            ShellPluginManagerPlanLabAction()
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true))
            XCTAssertTrue(plan.dryRun && plan.success, "\(id)")
            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false))
            XCTAssertTrue(install.success && !install.artifacts.isEmpty, "\(id) install")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a) && a.hasPrefix(root.path))
            }
            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false))
            XCTAssertTrue(remove.success)
            for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
        }
    }

    func testWave14LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            AutomatorWorkflowPlanLabAction(),
            IcloudDrivePathPlanLabAction(),
            BluetoothContinuityDepthPlanLabAction(),
            FontValidationDualusePlanLabAction(),
            QuicklookCacheDepthPlanLabAction(),
            DnsResolverDualusePlanLabAction(),
            LsQuarantineDbDepthPlanLabAction(),
            PamAuthModulePlanLabAction(),
            CronAtJobDepthPlanLabAction(),
            NotesMetadataPlanePlanLabAction()
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(actionId: type(of: action).id, operation: .plan, parameters: ["labRoot": "/tmp"]),
                    context: bad)
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized, got \(error)"); return
                }
            } catch { XCTFail("unexpected \(error)") }
        }
    }

    func testWave14LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave14-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            AutomatorWorkflowPlanLabAction(),
            IcloudDrivePathPlanLabAction(),
            BluetoothContinuityDepthPlanLabAction(),
            FontValidationDualusePlanLabAction(),
            QuicklookCacheDepthPlanLabAction(),
            DnsResolverDualusePlanLabAction(),
            LsQuarantineDbDepthPlanLabAction(),
            PamAuthModulePlanLabAction(),
            CronAtJobDepthPlanLabAction(),
            NotesMetadataPlanePlanLabAction()
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true))
            XCTAssertTrue(plan.dryRun && plan.success, "\(id)")
            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false))
            XCTAssertTrue(install.success && !install.artifacts.isEmpty, "\(id) install")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a) && a.hasPrefix(root.path))
            }
            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false))
            XCTAssertTrue(remove.success)
            for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
        }
    }

    func testWave13LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            CalendarRemindersPlanLabAction(),
            GatekeeperAssessmentHistoryPlanLabAction(),
            HomebrewPackagePlanLabAction(),
            CupsPrintPlanLabAction(),
            ScreenCapturePrivacyPlanLabAction()
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(actionId: type(of: action).id, operation: .plan, parameters: ["labRoot": "/tmp"]),
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

    func testWave13LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave13-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            CalendarRemindersPlanLabAction(),
            GatekeeperAssessmentHistoryPlanLabAction(),
            HomebrewPackagePlanLabAction(),
            CupsPrintPlanLabAction(),
            ScreenCapturePrivacyPlanLabAction()
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true)
            )
            XCTAssertTrue(plan.dryRun && plan.success, "\(id) plan")
            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success && !install.artifacts.isEmpty, "\(id) install")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a))
                XCTAssertTrue(a.hasPrefix(root.path))
            }
            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(remove.success)
            for a in install.artifacts {
                XCTAssertFalse(FileManager.default.fileExists(atPath: a))
            }
        }
    }

    func testWave12LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            WeblocInetlocPlanLabAction(),
            MailRulesAutomationPlanLabAction(),
            UnifiedLogObservationPlanLabAction(),
            DockPersistencePlanLabAction(),
            OsascriptScptPlanLabAction(),
            NetworkShareMountPlanLabAction()
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
}
