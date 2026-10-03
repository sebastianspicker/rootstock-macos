import Foundation
import Testing
import RootstockCore
import RootstockLab

@Suite struct ActionRegistryProofTests {
    @Test func markerLifecycleRejectsIntermediateSymlinkEscape() throws {
        let scratch = try makeTemporaryLabRoot()
        defer { removeTemporaryLabRoot(scratch) }
        let labRoot = scratch.appendingPathComponent("lab", isDirectory: true)
        let outside = scratch.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: labRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(
            at: labRoot.appendingPathComponent("linked"),
            withDestinationURL: outside
        )
        let marker = labRoot.appendingPathComponent("linked/marker.txt")

        #expect(throws: (any Error).self) {
            try LabMarkerLifecycle.writeMarker(at: marker, body: "synthetic")
        }
        #expect(!FileManager.default.fileExists(atPath: outside.appendingPathComponent("marker.txt").path))
    }

    @Test func productionActionIDsAreNonEmptyUniqueAndResolvable() {
        let registry = ActionRegistry.production()
        let ids = registry.actions.map { type(of: $0).id }

        #expect(!ids.isEmpty)
        #expect(ids.count == Set(ids).count, "production action IDs must be unique")
        #expect(ids.allSatisfy { !$0.isEmpty }, "production action IDs must be non-empty")
        #expect(registry.actionIds == ids.sorted())

        for id in ids {
            #expect(type(of: registry.action(id: id)!).id == id)
        }
    }

    @Test func everyProductionActionPlansAndDryRunsWithoutMutation() async throws {
        let root = try makeTemporaryLabRoot()
        defer { removeTemporaryLabRoot(root) }

        let pipeline = LabPipeline()
        let context = testConsentContext(dryRun: true)

        for id in pipeline.registry.actionIds {
            let plan = try await pipeline.run(
                request: request(for: id, operation: .plan, root: root),
                context: context
            )
            #expect(plan.success, "plan failed for \(id)")
            #expect(plan.dryRun, "plan must remain dry-run for \(id)")
            #expect(plan.actionId == id)
            assertArtifactsStayUnderTemporaryRoot(plan, root: root)

            let dryRun = try await pipeline.run(
                request: request(for: id, operation: .install, root: root),
                context: context
            )
            #expect(dryRun.success, "dry-run install failed for \(id)")
            #expect(dryRun.dryRun, "install must remain dry-run for \(id)")
            #expect(dryRun.actionId == id)
            assertArtifactsStayUnderTemporaryRoot(dryRun, root: root)
        }

        #expect(directoryContents(at: root).isEmpty, "plan and dry-run must not write under the test root")
    }

    @Test func absentAndPartialConsentFailClosedForEveryProductionAction() async throws {
        let root = try makeTemporaryLabRoot()
        defer { removeTemporaryLabRoot(root) }

        let pipeline = LabPipeline()
        let missingConsent = EvaluationContext(mode: .lab, dryRun: true)
        let partialConsent = EvaluationContext(
            mode: .lab,
            dryRun: true,
            consent: ConsentTokens(iAmAuthorized: true, scope: "TEST-SYNTHETIC-SCOPE")
        )

        for id in pipeline.registry.actionIds {
            await assertRunThrows(
                pipeline: pipeline,
                request: request(for: id, operation: .plan, root: root),
                context: missingConsent,
                message: "missing consent unexpectedly ran \(id)"
            )
            await assertRunThrows(
                pipeline: pipeline,
                request: request(for: id, operation: .plan, root: root),
                context: partialConsent,
                message: "partial consent unexpectedly ran \(id)"
            )
        }

        let noConfirm = EvaluationContext(
            mode: .lab,
            dryRun: true,
            consent: ConsentTokens(
                iAmAuthorized: true,
                scope: "TEST-SYNTHETIC-SCOPE",
                operatorName: "test-operator"
            )
        )
        await assertRunThrows(
            pipeline: pipeline,
            request: request(for: NoopLabAction.id, operation: .plan, root: root),
            context: noConfirm,
            message: "noop action must require its action-specific confirmation token"
        )
        #expect(directoryContents(at: root).isEmpty, "rejected requests must not mutate the test root")
    }

    @Test func representativeReversibleLifecyclesApplyStatusAndRemoveInTemporaryRoot() async throws {
        let root = try makeTemporaryLabRoot()
        defer { removeTemporaryLabRoot(root) }

        let pipeline = LabPipeline()
        let context = testConsentContext(dryRun: false)

        try await assertLifecycle(
            actionID: DylibSurfaceLabAction.id,
            pipeline: pipeline,
            context: context,
            root: root
        )
        try await assertLifecycle(
            actionID: LaunchAgentLabAction.id,
            pipeline: pipeline,
            context: context,
            root: root
        )
        try await assertLifecycle(
            actionID: AppSandboxPlanLabAction.id,
            pipeline: pipeline,
            context: context,
            root: root
        )
    }

    private func assertLifecycle(
        actionID: String,
        pipeline: LabPipeline,
        context: EvaluationContext,
        root: URL
    ) async throws {
        let install = try await pipeline.run(
            request: request(for: actionID, operation: .install, root: root),
            context: context
        )
        #expect(install.success, "install failed for \(actionID)")
        #expect(!install.dryRun, "explicit test consent should permit only temporary-root marker writes")
        #expect(!install.artifacts.isEmpty, "install should report a reversible artifact for \(actionID)")
        assertArtifactsStayUnderTemporaryRoot(install, root: root)
        #expect(install.artifacts.allSatisfy { FileManager.default.fileExists(atPath: $0) })

        let present = try await pipeline.run(
            request: request(for: actionID, operation: .status, root: root),
            context: context
        )
        #expect(present.success, "status failed for \(actionID)")
        #expect(!present.artifacts.isEmpty, "status should find the temporary-root artifact for \(actionID)")
        assertArtifactsStayUnderTemporaryRoot(present, root: root)

        let remove = try await pipeline.run(
            request: request(for: actionID, operation: .remove, root: root),
            context: context
        )
        #expect(remove.success, "remove failed for \(actionID)")
        #expect(!remove.dryRun, "remove should be a real temporary-root cleanup for \(actionID)")
        assertArtifactsStayUnderTemporaryRoot(remove, root: root)

        let absent = try await pipeline.run(
            request: request(for: actionID, operation: .status, root: root),
            context: context
        )
        #expect(absent.success, "post-remove status failed for \(actionID)")
        #expect(absent.artifacts.isEmpty, "removed artifact must be absent for \(actionID)")
    }

    private func testConsentContext(dryRun: Bool) -> EvaluationContext {
        EvaluationContext(
            mode: .lab,
            dryRun: dryRun,
            consent: ConsentTokens(
                iAmAuthorized: true,
                scope: "TEST-SYNTHETIC-SCOPE",
                operatorName: "test-operator",
                confirm: "lab.noop"
            )
        )
    }

    private func request(for actionID: String, operation: LabOperation, root: URL) -> LabActionRequest {
        LabActionRequest(
            actionId: actionID,
            operation: operation,
            parameters: [
                "labRoot": root.path,
                "directory": root.appendingPathComponent("launch-agents", isDirectory: true).path,
                "rcFile": root.appendingPathComponent("shell", isDirectory: true).appendingPathComponent(".zshrc").path,
                "app": "test-app",
                "label": "com.rootstock.red.lab.test",
            ]
        )
    }

    private func makeTemporaryLabRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-red-lab-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root.standardizedFileURL
    }

    private func removeTemporaryLabRoot(_ root: URL) {
        try? FileManager.default.removeItem(at: root)
    }

    private func directoryContents(at root: URL) -> [URL] {
        (try? FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )) ?? []
    }

    private func assertArtifactsStayUnderTemporaryRoot(_ result: ActionResult, root: URL) {
        let prefix = root.standardizedFileURL.path + "/"
        for artifact in result.artifacts {
            #expect(URL(fileURLWithPath: artifact).standardizedFileURL.path.hasPrefix(prefix), "artifact escaped the temporary root: \(artifact)")
        }
    }

    private func assertRunThrows(
        pipeline: LabPipeline,
        request: LabActionRequest,
        context: EvaluationContext,
        message: String
    ) async {
        do {
            _ = try await pipeline.run(request: request, context: context)
            Issue.record("\(message)")
        } catch {
            // Expected: consent must fail before any lab action is routed.
        }
    }
}
