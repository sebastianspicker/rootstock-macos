import XCTest
import RootstockCore
import MacEnumKit
import MacArtifactKit
@testable import MacVulnKit

extension AttackVectorTests {
    func testAttackVectorIdsRegistered() {
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        for id in AttackVectorPlane.ids {
            XCTAssertTrue(registered.contains(id), "vector \(id) not in allChecks()")
        }
        for id in AttackVectorTestFixtures.requiredVectorIDs {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing registered vector \(id)")
        }
        for minimum in AttackVectorTestFixtures.minimumVectorCounts {
            XCTAssertGreaterThanOrEqual(AttackVectorPlane.ids.count, minimum)
        }
        XCTAssertEqual(AttackVectorPlane.allChecks().count, AttackVectorPlane.ids.count)
        for check in AttackVectorPlane.allChecks() {
            XCTAssertEqual(type(of: check).cost, .low, "\(type(of: check).id) should be .low")
        }
    }
}
