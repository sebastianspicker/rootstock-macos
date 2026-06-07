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
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["user"] as? String, "deploy")
        XCTAssertEqual(json["nopasswd"] as? Bool, true)
    }

    func testParseSudoersContentExtractsPrivilegeRulesAndSkipsNonRules() {
        let content = """
        # Sudoers file
        Defaults env_reset
        User_Alias ADMINS = alice,bob
        Cmnd_Alias PACKAGE = /usr/sbin/installer
        Runas_Alias ROOT = root
        #includedir /etc/sudoers.d
        @includedir /private/etc/sudoers.d
        root ALL = (ALL) ALL
        %admin ALL = (ALL) ALL
        deploy ALL = (ALL) NOPASSWD: /usr/bin/systemctl restart nginx
        operator WEBHOSTS = (ROOT) PASSWD: /usr/bin/vi
        ADMINS ALL = (ROOT) NOPASSWD: PACKAGE
        this is not a valid sudoers rule
        broken =
        """
        let rules = SudoersDataSource.parseSudoersContent(content)
        XCTAssertEqual(rules.count, 5)

        assertRule(rules, user: "root", host: "ALL", command: "ALL", nopasswd: false)
        assertRule(rules, user: "%admin", host: "ALL", command: "ALL", nopasswd: false)
        assertRule(
            rules,
            user: "deploy",
            host: "ALL",
            command: "/usr/bin/systemctl restart nginx",
            nopasswd: true
        )
        assertRule(rules, user: "operator", host: "WEBHOSTS", command: "/usr/bin/vi", nopasswd: false)
        assertRule(rules, user: "ADMINS", host: "ALL", command: "PACKAGE", nopasswd: true)

        XCTAssertFalse(rules.contains { $0.user == "User_Alias" })
        XCTAssertFalse(rules.contains { $0.command == "/private/etc/sudoers.d" })
    }

    func testSudoersDataSourceCollectsFixtureRulesAndIncludedFiles() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let sudoersPath = tempDir.appendingPathComponent("sudoers")
        let includeDir = tempDir.appendingPathComponent("sudoers.d")
        try FileManager.default.createDirectory(at: includeDir, withIntermediateDirectories: true)
        try """
        root ALL = (ALL) ALL
        deploy ALL = (root) NOPASSWD: /usr/bin/systemctl restart nginx
        """.write(to: sudoersPath, atomically: true, encoding: .utf8)
        try """
        %wheel ALL = (ALL) NOPASSWD: /usr/bin/dscl
        """.write(to: includeDir.appendingPathComponent("10-wheel"), atomically: true, encoding: .utf8)
        try """
        hidden ALL = (ALL) NOPASSWD: ALL
        """.write(to: includeDir.appendingPathComponent(".ignored"), atomically: true, encoding: .utf8)

        let result = await SudoersDataSource(
            sudoersPath: sudoersPath.path,
            includeDirectoryPath: includeDir.path
        ).collect()
        let rules = result.nodes.compactMap { $0 as? SudoersRule }

        XCTAssertTrue(result.errors.isEmpty)
        XCTAssertEqual(rules.count, 3)
        assertRule(rules, user: "root", host: "ALL", command: "ALL", nopasswd: false)
        assertRule(
            rules,
            user: "deploy",
            host: "ALL",
            command: "/usr/bin/systemctl restart nginx",
            nopasswd: true
        )
        assertRule(rules, user: "%wheel", host: "ALL", command: "/usr/bin/dscl", nopasswd: true)
        XCTAssertFalse(rules.contains { $0.user == "hidden" })
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

    func testSudoersDataSourceReportsMissingMainFile() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let missingSudoersPath = tempDir.appendingPathComponent("missing-sudoers")
        let result = await SudoersDataSource(
            sudoersPath: missingSudoersPath.path,
            includeDirectoryPath: tempDir.appendingPathComponent("missing-sudoers.d").path
        ).collect()

        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.errors.count, 1)
        XCTAssertEqual(result.errors.first?.source, "Sudoers")
        XCTAssertEqual(result.errors.first?.recoverable, true)
        XCTAssertTrue(result.errors.first?.message.contains("Cannot read sudoers file") ?? false)
        XCTAssertTrue(result.errors.first?.message.contains(missingSudoersPath.path) ?? false)
    }

    func testSudoersDataSourceReportsUnreadableMainPathAndKeepsIncludedRules() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let includeDir = tempDir.appendingPathComponent("sudoers.d")
        try FileManager.default.createDirectory(at: includeDir, withIntermediateDirectories: true)
        try """
        %admin ALL = (ALL) NOPASSWD: ALL
        """.write(to: includeDir.appendingPathComponent("admin"), atomically: true, encoding: .utf8)

        let result = await SudoersDataSource(
            sudoersPath: tempDir.path,
            includeDirectoryPath: includeDir.path
        ).collect()
        let rules = result.nodes.compactMap { $0 as? SudoersRule }

        XCTAssertEqual(rules.count, 1)
        assertRule(rules, user: "%admin", host: "ALL", command: "ALL", nopasswd: true)
        XCTAssertEqual(result.errors.count, 1)
        XCTAssertEqual(result.errors.first?.recoverable, true)
        XCTAssertTrue(result.errors.first?.message.contains("Cannot read sudoers file") ?? false)
    }

    func testSudoersDataSourceReportsUnlistableIncludePath() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let sudoersPath = tempDir.appendingPathComponent("sudoers")
        let includeFile = tempDir.appendingPathComponent("sudoers.d")
        try "root ALL = (ALL) ALL".write(to: sudoersPath, atomically: true, encoding: .utf8)
        try "not a directory".write(to: includeFile, atomically: true, encoding: .utf8)

        let result = await SudoersDataSource(
            sudoersPath: sudoersPath.path,
            includeDirectoryPath: includeFile.path
        ).collect()
        let rules = result.nodes.compactMap { $0 as? SudoersRule }

        XCTAssertEqual(rules.count, 1)
        assertRule(rules, user: "root", host: "ALL", command: "ALL", nopasswd: false)
        XCTAssertEqual(result.errors.count, 1)
        XCTAssertEqual(result.errors.first?.recoverable, true)
        XCTAssertTrue(result.errors.first?.message.contains("Cannot list sudoers include directory") ?? false)
    }

    private func assertRule(
        _ rules: [SudoersRule],
        user: String,
        host: String,
        command: String,
        nopasswd: Bool,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let rule = rules.first { $0.user == user && $0.command == command }
        XCTAssertNotNil(rule, "Missing sudoers rule for \(user) -> \(command)", file: file, line: line)
        XCTAssertEqual(rule?.host, host, file: file, line: line)
        XCTAssertEqual(rule?.nopasswd, nopasswd, file: file, line: line)
    }

    private func makeTempDirectory() throws -> URL {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("rootstock-sudoers-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        return tempDir
    }
}
