import XCTest
import Foundation
@testable import ShellHooks
import Models

final class ShellHookTests: XCTestCase {

    func testDataSourceMetadata() {
        let ds = ShellHookDataSource()
        XCTAssertEqual(ds.name, "Shell Hooks")
        XCTAssertFalse(ds.requiresElevation)
    }

    func testHookPathsNotEmpty() {
        XCTAssertGreaterThan(ShellHookDataSource.hookPaths.count, 0)
    }

    func testDataSourceCollectsWithoutCrash() async {
        let ds = ShellHookDataSource()
        let result = await ds.collect()
        XCTAssertGreaterThanOrEqual(result.nodes.count, 0)
        for node in result.nodes {
            guard let acl = node as? FileACL else {
                XCTFail("Expected FileACL node")
                continue
            }
            XCTAssertEqual(acl.category, "shell_hook")
        }
    }
}
