@testable import RootstockCLI
import XCTest

final class ModuleConfigTests: XCTestCase {
    func testAllEnablesEveryModule() throws {
        let config = try ScanOrchestrator.ModuleConfig.from("all")

        XCTAssertEqual(
            config.selectedModuleNames,
            Set(ScanOrchestrator.ModuleConfig.moduleNames)
        )
    }

    func testParsesDocumentedModuleNames() throws {
        let config = try ScanOrchestrator.ModuleConfig.from(
            """
            tcc, entitlements, codesigning, xpc, persistence, keychain, mdm, groups,
            remoteaccess, firewall, loginsessions, authorizationdb, authplugins,
            systemextensions, sudoers, processsnapshot, fileacls, shellhooks,
            physicalsecurity, activedirectory, kerberos, sandbox, quarantine
            """
        )

        XCTAssertEqual(
            config.selectedModuleNames,
            Set(ScanOrchestrator.ModuleConfig.moduleNames)
        )
    }

    func testModuleRegistryControlsHelpAndSupportedNames() {
        XCTAssertEqual(
            ScanOrchestrator.ModuleConfig.supportedModuleHelp,
            ScanOrchestrator.ModuleConfig.moduleNames.joined(separator: ", ")
        )
        XCTAssertEqual(
            ScanOrchestrator.ModuleConfig.supportedModuleNames,
            Set(["all"] + ScanOrchestrator.ModuleConfig.moduleNames)
        )
    }

    func testIndependentModuleRegistryMapsAllSixteenModulesExactlyOnce() {
        let expected: [RootstockModuleID] = [
            .tcc,
            .xpc,
            .persistence,
            .keychain,
            .mdm,
            .groups,
            .remoteAccess,
            .firewall,
            .loginSessions,
            .authorizationDB,
            .authorizationPlugins,
            .systemExtensions,
            .sudoers,
            .fileACLs,
            .shellHooks,
            .kerberos,
        ]
        let registered = ScanOrchestrator.independentModuleIDs

        XCTAssertEqual(registered, expected)
        XCTAssertEqual(registered.count, 16)
        XCTAssertEqual(Set(registered).count, registered.count)
        XCTAssertEqual(
            Set(ScanOrchestrator.independentModules.map(\.id)),
            Set(expected),
            "Every registered ID must have exactly one collection mapping"
        )
    }

    func testParsesWhitespaceAndDuplicateModuleNames() throws {
        let config = try ScanOrchestrator.ModuleConfig.from(" tcc, tcc, entitlements ")

        XCTAssertEqual(config.selectedModuleNames, Set(["tcc", "entitlements"]))
        XCTAssertTrue(config.includes(.tcc))
        XCTAssertTrue(config.includes(.entitlements))
        XCTAssertFalse(config.includes(.codeSigning))
    }

    func testRejectsUnknownModuleNames() {
        XCTAssertThrowsError(try ScanOrchestrator.ModuleConfig.from("tcc,typo")) { error in
            XCTAssertTrue(String(describing: error).contains("Unknown module(s): typo"))
        }
    }

    func testRejectsSandboxWithoutEntitlements() {
        XCTAssertThrowsError(try ScanOrchestrator.ModuleConfig.from("sandbox")) { error in
            XCTAssertTrue(
                String(describing: error)
                    .contains("Module 'sandbox' requires module 'entitlements'")
            )
        }
    }

    func testRejectsQuarantineWithoutEntitlements() {
        XCTAssertThrowsError(try ScanOrchestrator.ModuleConfig.from("quarantine")) { error in
            XCTAssertTrue(
                String(describing: error)
                    .contains("Module 'quarantine' requires module 'entitlements'")
            )
        }
    }

    func testAllowsEnrichmentModulesWithEntitlements() throws {
        let config = try ScanOrchestrator.ModuleConfig.from("entitlements,sandbox,quarantine")

        XCTAssertEqual(
            config.selectedModuleNames,
            Set(["entitlements", "sandbox", "quarantine"])
        )
    }
}
