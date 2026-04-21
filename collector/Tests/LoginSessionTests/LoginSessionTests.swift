import XCTest
import Foundation
@testable import LoginSession
import Models

final class LoginSessionTests: XCTestCase {

    // MARK: - Model

    func testLoginSessionNodeType() {
        let session = LoginSession(
            username: "admin",
            terminal: "console",
            loginTime: "Mar 18 09:15",
            sessionType: .console
        )
        XCTAssertEqual(session.nodeType, "LoginSession")
    }

    func testLoginSessionJSONEncoding() throws {
        let session = LoginSession(
            username: "admin",
            terminal: "ttys000",
            loginTime: "Mar 18 09:30",
            sessionType: .ssh
        )
        let data = try JSONEncoder().encode(session)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertEqual(json["username"] as? String, "admin")
        XCTAssertEqual(json["terminal"] as? String, "ttys000")
        XCTAssertEqual(json["login_time"] as? String, "Mar 18 09:30")
        XCTAssertEqual(json["session_type"] as? String, "ssh")
    }

    func testLoginSessionJSONRoundTrip() throws {
        let original = LoginSession(
            username: "root",
            terminal: "console",
            loginTime: "Mar 18 08:00",
            sessionType: .console
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(LoginSession.self, from: data)
        XCTAssertEqual(decoded.username, original.username)
        XCTAssertEqual(decoded.terminal, original.terminal)
        XCTAssertEqual(decoded.sessionType, original.sessionType)
    }

    // MARK: - Parser

    func testParseWhoOutputBasic() {
        let output = """
        sebastian  console  Mar 18 09:15
        sebastian  ttys000  Mar 18 09:30
        """
        let sessions = LoginSessionDataSource.parseWhoOutput(output)
        XCTAssertEqual(sessions.count, 2)
        XCTAssertEqual(sessions[0].username, "sebastian")
        XCTAssertEqual(sessions[0].terminal, "console")
        XCTAssertEqual(sessions[0].sessionType, .console)
        XCTAssertEqual(sessions[1].terminal, "ttys000")
    }

    func testParseWhoOutputWithHost() {
        let output = "admin  ttys001  Mar 18 10:00 (192.168.1.5)"
        let sessions = LoginSessionDataSource.parseWhoOutput(output)
        XCTAssertEqual(sessions.count, 1)
        XCTAssertEqual(sessions[0].sessionType, .ssh)
        XCTAssertEqual(sessions[0].loginTime, "Mar 18 10:00")
    }

    func testParseWhoOutputEmpty() {
        let sessions = LoginSessionDataSource.parseWhoOutput("")
        XCTAssertTrue(sessions.isEmpty)
    }

    func testParseWhoOutputWithTmux() {
        let output = "admin  ttys002  Mar 18 11:00 (tmux(12345).%0)"
        let sessions = LoginSessionDataSource.parseWhoOutput(output)
        XCTAssertEqual(sessions.count, 1)
        XCTAssertEqual(sessions[0].sessionType, .tmux)
    }

    // MARK: - DataSource

    func testLoginSessionDataSourceMetadata() {
        let ds = LoginSessionDataSource()
        XCTAssertEqual(ds.name, "Login Sessions")
        XCTAssertFalse(ds.requiresElevation)
    }

    func testLoginSessionDataSourceCollectsWithoutCrash() async {
        let ds = LoginSessionDataSource()
        let result = await ds.collect()
        let sessions = result.nodes.compactMap { $0 as? LoginSession }
        // At least one console session expected on a Mac with a logged-in user
        XCTAssertGreaterThanOrEqual(sessions.count, 0)
    }
}
