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
        XCTAssertTrue(result.errors.allSatisfy(\.recoverable))
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

    func testCollectsAllConfiguredSecurityRelevantGroupsFromDirectoryServiceOutput() async {
        let expectedGroups: [String: Int] = [
            "admin": 80,
            "wheel": 0,
            "staff": 20,
            "_developer": 204,
            "com.apple.access_ssh": 398,
            "com.apple.access_screensharing": 399,
            "_lpadmin": 98,
            "com.apple.access_ftp": 395,
        ]
        let source = GroupDataSource(runCommand: { _, arguments in
            if arguments == [".", "-list", "/Groups", "PrimaryGroupID"] {
                var listedGroups = expectedGroups
                listedGroups["_analyticsusers"] = 250
                return listedGroups
                    .map { "\($0.key) \($0.value)" }
                    .joined(separator: "\n")
            }

            if arguments.count == 4,
               arguments[0] == ".",
               arguments[1] == "-read",
               arguments[2].hasPrefix("/Groups/"),
               arguments[3] == "GroupMembership" {
                return "GroupMembership: alice"
            }

            if arguments.count == 5,
               arguments[0] == ".",
               arguments[1] == "-read",
               arguments[2] == "/Users/alice" {
                return "UserShell: /bin/zsh\nNFSHomeDirectory: /Users/alice\nIsHidden: 0"
            }

            return nil
        })

        let result = await source.collect()
        let groups = result.nodes.compactMap { $0 as? LocalGroup }
        let actual: [String: Int] = Dictionary(uniqueKeysWithValues: groups.map { ($0.name, $0.gid) })

        XCTAssertEqual(actual, expectedGroups)
        XCTAssertTrue(result.errors.isEmpty)
    }

    func testDirectoryServiceFailureReturnsRecoverableError() async {
        let source = GroupDataSource(runCommand: { _, _ in nil })
        let result = await source.collect()

        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.errors.count, 1)
        XCTAssertEqual(result.errors[0].source, "Groups")
        XCTAssertTrue(result.errors[0].message.contains("No security-relevant groups"))
        XCTAssertTrue(result.errors[0].recoverable)
    }
}
