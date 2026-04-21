import XCTest
@testable import Groups
import Models

final class GroupTests: XCTestCase {

    // MARK: - Model tests

    func testLocalGroupNodeType() {
        let group = LocalGroup(name: "admin", gid: 80, members: ["testuser"])
        XCTAssertEqual(group.nodeType, "LocalGroup")
    }

    func testLocalGroupJSONEncoding() throws {
        let group = LocalGroup(name: "wheel", gid: 0, members: ["root", "admin"])
        let data = try JSONEncoder().encode(group)
        let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(dict?["name"] as? String, "wheel")
        XCTAssertEqual(dict?["gid"] as? Int, 0)
        XCTAssertEqual(dict?["members"] as? [String], ["root", "admin"])
    }

    func testLocalGroupJSONRoundTrip() throws {
        let original = LocalGroup(name: "admin", gid: 80, members: ["user1", "user2"])
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(LocalGroup.self, from: data)
        XCTAssertEqual(decoded.name, original.name)
        XCTAssertEqual(decoded.gid, original.gid)
        XCTAssertEqual(decoded.members, original.members)
    }

    func testEmptyMembersIsValid() throws {
        let group = LocalGroup(name: "_developer", gid: 204, members: [])
        let data = try JSONEncoder().encode(group)
        let decoded = try JSONDecoder().decode(LocalGroup.self, from: data)
        XCTAssertTrue(decoded.members.isEmpty)
    }

    // MARK: - DataSource tests

    func testGroupDataSourceMetadata() {
        let source = GroupDataSource()
        XCTAssertEqual(source.name, "Local Groups")
        XCTAssertFalse(source.requiresElevation)
    }

    func testGroupDataSourceCollectsWithoutCrash() async {
        let source = GroupDataSource()
        let result = await source.collect()
        // Should always find at least admin + staff on any macOS system
        let groups = result.nodes.compactMap { $0 as? LocalGroup }
        XCTAssertFalse(groups.isEmpty, "Should find at least one security-relevant group")
    }

    func testAdminGroupExists() async throws {
        let source = GroupDataSource()
        let result = await source.collect()
        let groups = result.nodes.compactMap { $0 as? LocalGroup }
        let adminGroup = groups.first { $0.name == "admin" }
        guard let admin = adminGroup else {
            throw XCTSkip("admin group is not present on this host")
        }
        XCTAssertEqual(admin.gid, 80, "admin group GID should be 80")
        XCTAssertFalse(admin.members.isEmpty, "admin group should have at least one member")
    }

    func testStaffGroupExists() async {
        let source = GroupDataSource()
        let result = await source.collect()
        let groups = result.nodes.compactMap { $0 as? LocalGroup }
        let staffGroup = groups.first { $0.name == "staff" }
        XCTAssertNotNil(staffGroup, "staff group should exist on macOS")
    }

    func testOnlySecurityRelevantGroupsCollected() async {
        let source = GroupDataSource()
        let result = await source.collect()
        let groups = result.nodes.compactMap { $0 as? LocalGroup }
        for group in groups {
            XCTAssertTrue(
                GroupDataSource.securityRelevantGroups.contains(group.name),
                "Unexpected group '\(group.name)' — should only collect security-relevant groups"
            )
        }
    }

    func testErrorsAreRecoverable() async {
        let source = GroupDataSource()
        let result = await source.collect()
        for error in result.errors {
            XCTAssertTrue(error.recoverable, "All group errors should be recoverable")
        }
    }
}
