import XCTest
@testable import RemoteAccess
import Models

final class RemoteAccessTests: XCTestCase {

    // MARK: - Model tests

    func testRemoteAccessServiceNodeType() {
        let svc = RemoteAccessService(service: "ssh", enabled: true, port: 22, config: [:])
        XCTAssertEqual(svc.nodeType, "RemoteAccessService")
    }

    func testRemoteAccessServiceJSONEncoding() throws {
        let svc = RemoteAccessService(
            service: "ssh", enabled: true, port: 22,
            config: ["PermitRootLogin": "no"]
        )
        let data = try JSONEncoder().encode(svc)
        let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(dict?["service"] as? String, "ssh")
        XCTAssertEqual(dict?["enabled"] as? Bool, true)
        XCTAssertEqual(dict?["port"] as? Int, 22)
    }

    func testRemoteAccessServiceJSONRoundTrip() throws {
        let original = RemoteAccessService(
            service: "screen_sharing", enabled: false, port: nil, config: [:]
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(RemoteAccessService.self, from: data)
        XCTAssertEqual(decoded.service, "screen_sharing")
        XCTAssertEqual(decoded.enabled, false)
        XCTAssertNil(decoded.port)
    }

    // MARK: - SSH config parsing

    func testParseSSHConfigBasic() {
        let source = RemoteAccessDataSource()
        let config = """
        # Standard sshd config
        Port 2222
        PermitRootLogin no
        PasswordAuthentication yes
        PubkeyAuthentication yes
        # Other settings
        UseDNS no
        """
        let result = source.parseSSHConfig(config)
        XCTAssertEqual(result["Port"], "2222")
        XCTAssertEqual(result["PermitRootLogin"], "no")
        XCTAssertEqual(result["PasswordAuthentication"], "yes")
        XCTAssertEqual(result["PubkeyAuthentication"], "yes")
        // UseDNS is not in the interesting list
        XCTAssertNil(result["UseDNS"])
    }

    func testParseSSHConfigSkipsComments() {
        let source = RemoteAccessDataSource()
        let config = """
        # Port 22
        #PermitRootLogin yes
        PasswordAuthentication no
        """
        let result = source.parseSSHConfig(config)
        XCTAssertNil(result["Port"], "Commented-out Port should be ignored")
        XCTAssertNil(result["PermitRootLogin"], "Commented-out directive should be ignored")
        XCTAssertEqual(result["PasswordAuthentication"], "no")
    }

    func testParseSSHConfigEmpty() {
        let source = RemoteAccessDataSource()
        let result = source.parseSSHConfig("")
        XCTAssertTrue(result.isEmpty)
    }

    func testParseSSHConfigCaseInsensitive() {
        let source = RemoteAccessDataSource()
        let config = """
        port 2222
        permitrootlogin no
        passwordauthentication yes
        PUBKEYAUTHENTICATION yes
        """
        let result = source.parseSSHConfig(config)
        // All keys should be normalized to canonical casing
        XCTAssertEqual(result["Port"], "2222")
        XCTAssertEqual(result["PermitRootLogin"], "no")
        XCTAssertEqual(result["PasswordAuthentication"], "yes")
        XCTAssertEqual(result["PubkeyAuthentication"], "yes")
    }

    func testParseSSHConfigMixedCase() {
        let source = RemoteAccessDataSource()
        let config = "PermitRootLogin yes\nPort 22"
        let result = source.parseSSHConfig(config)
        XCTAssertEqual(result["PermitRootLogin"], "yes")
        XCTAssertEqual(result["Port"], "22")
    }

    // MARK: - DataSource tests

    func testRemoteAccessDataSourceMetadata() {
        let source = RemoteAccessDataSource()
        XCTAssertEqual(source.name, "Remote Access")
        XCTAssertFalse(source.requiresElevation)
    }

    func testRemoteAccessDataSourceCollectsWithoutCrash() async {
        let source = RemoteAccessDataSource()
        let result = await source.collect()
        let services = result.nodes.compactMap { $0 as? RemoteAccessService }
        // Should always return exactly 2 services: ssh + screen_sharing
        XCTAssertEqual(services.count, 2, "Should return both SSH and Screen Sharing status")
    }

    func testBothServicesPresent() async {
        let source = RemoteAccessDataSource()
        let result = await source.collect()
        let services = result.nodes.compactMap { $0 as? RemoteAccessService }
        let names = Set(services.map(\.service))
        XCTAssertTrue(names.contains("ssh"), "SSH service should always be reported")
        XCTAssertTrue(names.contains("screen_sharing"), "Screen sharing should always be reported")
    }

    func testErrorsAreRecoverable() async {
        let source = RemoteAccessDataSource()
        let result = await source.collect()
        for error in result.errors {
            XCTAssertTrue(error.recoverable, "All remote access errors should be recoverable")
        }
    }

    func testParseDisabledServices() {
        let output = "\"com.openssh.sshd\" => true\n\"com.apple.screensharing\" => false"
        let result = RemoteAccessDataSource.parseDisabledServices(output: output)
        XCTAssertEqual(result["com.openssh.sshd"], true)
        XCTAssertEqual(result["com.apple.screensharing"], false)
    }

    func testCommandFailureProducesUnknownState() async {
        let source = RemoteAccessDataSource(
            launchctlRunner: { _ in nil }
        )
        let result = await source.collect()
        let services = result.nodes.compactMap { $0 as? RemoteAccessService }

        XCTAssertEqual(services.count, 2)
        XCTAssertTrue(services.allSatisfy { $0.enabled == nil })
        XCTAssertFalse(result.errors.isEmpty)
    }
}
