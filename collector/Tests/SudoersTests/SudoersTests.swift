import XCTest
import Foundation
@testable import Sudoers
import Models

final class SudoersTests: XCTestCase {

    func testSudoersRuleNodeType() {
        let rule = SudoersRule(user: "admin", host: "ALL", command: "ALL", nopasswd: true)
        XCTAssertEqual(rule.nodeType, "SudoersRule")
    }

    func testSudoersRuleJSONEncoding() throws {
        let rule = SudoersRule(user: "deploy", host: "ALL", command: "/usr/bin/systemctl restart nginx", nopasswd: true)
        let data = try JSONEncoder().encode(rule)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(json["user"] as? String, "deploy")
        XCTAssertEqual(json["nopasswd"] as? Bool, true)
    }

    func testParseSudoersContentBasic() {
        let content = """
        # Sudoers file
        root ALL = (ALL) ALL
        %admin ALL = (ALL) ALL
        deploy ALL = (ALL) NOPASSWD: /usr/bin/systemctl restart nginx
        """
        let rules = SudoersDataSource.parseSudoersContent(content)
        XCTAssertGreaterThanOrEqual(rules.count, 3)

        let deployRule = rules.first { $0.user == "deploy" }
        XCTAssertNotNil(deployRule)
        XCTAssertTrue(deployRule?.nopasswd ?? false)
    }

    func testParseSudoersContentSkipsComments() {
        let content = """
        # This is a comment
        Defaults env_reset
        """
        let rules = SudoersDataSource.parseSudoersContent(content)
        XCTAssertTrue(rules.isEmpty)
    }

    func testParseSudoersContentEmpty() {
        let rules = SudoersDataSource.parseSudoersContent("")
        XCTAssertTrue(rules.isEmpty)
    }

    func testSudoersDataSourceMetadata() {
        let ds = SudoersDataSource()
        XCTAssertEqual(ds.name, "Sudoers")
        XCTAssertFalse(ds.requiresElevation)
    }

    func testSudoersDataSourceCollectsWithoutCrash() async {
        let ds = SudoersDataSource()
        let result = await ds.collect()
        XCTAssertGreaterThanOrEqual(result.nodes.count, 0)
    }
}
