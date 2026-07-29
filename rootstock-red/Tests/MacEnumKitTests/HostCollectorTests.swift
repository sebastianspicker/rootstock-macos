import XCTest
import RootstockCore
@testable import MacEnumKit

final class HostCollectorTests: XCTestCase {
    func testHostCollectorReturnsHost() async throws {
        let state = try await HostCollector().collect(context: .assess())
        XCTAssertNotNil(state.host)
        XCTAssertFalse(state.host?.hostname.isEmpty ?? true)
        XCTAssertFalse(state.host?.username.isEmpty ?? true)
        XCTAssertFalse(state.host?.osVersion.isEmpty ?? true)
    }

    func testRegistryHasExpectedCollectors() {
        let ids = Set(EnumModuleRegistry.allCollectors().map { type(of: $0).id })
        XCTAssertTrue(ids.contains("collect.host"))
        XCTAssertTrue(ids.contains("collect.security_products"))
        XCTAssertTrue(ids.contains("collect.launchd"))
        XCTAssertTrue(ids.contains("collect.tcc_graph"))
        XCTAssertTrue(ids.contains("collect.loobins"))
    }
}
