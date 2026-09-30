import Testing
@testable import Models
@testable import RootstockCLI

@Suite struct ScanOrchestratorTests {
    @Test func moduleConfigNormalizesWhitespaceAndDuplicates() throws {
        let config = try ScanOrchestrator.ModuleConfig.from(" tcc, entitlements, tcc ")

        #expect(config.selectedModuleNames == ["entitlements", "tcc"])
        #expect(config.includes(.tcc))
        #expect(config.includes(.entitlements))
        #expect(!(config.includes(.xpc)))
    }

    @Test func moduleConfigAllSelectsEveryModule() throws {
        let config = try ScanOrchestrator.ModuleConfig.from("all, tcc")

        #expect(config.selectedModuleNames == Set(RootstockModuleID.allCases.map(\.rawValue)))
    }

    @Test func moduleConfigRejectsSortedUnknownModules() {
        do {
            _ = try ScanOrchestrator.ModuleConfig.from("tcc, zebra, alpha")
            Issue.record("Expected error to be thrown")
        } catch {
            guard case let .unknownModules(modules) = error as? RootstockModuleConfigError else {
                Issue.record("Expected unknown module error, got \(error)")
                return
            }
            #expect(modules == ["alpha", "zebra"])
        }
    }

    @Test func applicationEnrichmentsRequireEntitlements() {
        for module in ["sandbox", "quarantine", "sandbox, quarantine"] {
            do {
                _ = try ScanOrchestrator.ModuleConfig.from(module)
                Issue.record("Expected error to be thrown")
            } catch {
                guard case let .missingPrerequisites(messages) = error as? RootstockModuleConfigError else {
                    Issue.record("Expected entitlement prerequisite error, got \(error)")
                    continue
                }
                #expect(!messages.isEmpty)
                #expect(messages.allSatisfy { $0.contains("requires module 'entitlements'") })
            }
        }
    }

    @Test func injectedExecutionReturnsCanonicalScanWithoutHostCollection() async throws {
        let expected = canonicalScan()
        let orchestrator = ScanOrchestrator(
            verbose: false,
            execution: .injected { config in
                #expect(config.includes(.tcc))
                return expected
            }
        )
        let config = try ScanOrchestrator.ModuleConfig.from("tcc")

        let actual = await orchestrator.run(config: config)

        #expect(actual.scanId == "canonical-scan")
        #expect(actual.timestamp == "2026-09-04T00:00:00Z")
        #expect(actual.hostname == "fixture-host")
        #expect(actual.collectorVersion == "0.1.0-alpha.1")
        #expect(actual.applications.isEmpty)
        #expect(actual.errors.isEmpty)
    }

    private func canonicalScan() -> ScanResult {
        ScanResult(
            metadata: .init(
                scanId: "canonical-scan",
                timestamp: "2026-09-04T00:00:00Z",
                hostname: "fixture-host",
                macosVersion: "macOS 26.0",
                collectorVersion: "0.1.0-alpha.1"
            ),
            elevation: .init(isRoot: false, hasFda: false),
            errors: []
        )
    }
}
