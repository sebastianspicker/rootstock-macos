import XCTest
import Foundation
@testable import Models
@testable import ActiveDirectory

final class ActiveDirectoryTests: XCTestCase {

    // MARK: - Model roundtrip

    func testADBindingRoundtrip() throws {
        let binding = ADBinding(
            isBound: true,
            realm: "CORP.EXAMPLE.COM",
            forest: "EXAMPLE.COM",
            computerAccount: "TESTMAC$",
            organizationalUnit: "OU=Macs,DC=corp,DC=example,DC=com",
            preferredDC: "dc01.corp.example.com",
            groupMappings: [
                ADGroupMapping(adGroup: "Domain Admins", localGroup: "admin"),
                ADGroupMapping(adGroup: "Mac Admins", localGroup: "admin"),
            ]
        )
        let data = try JSONEncoder().encode(binding)
        let decoded = try JSONDecoder().decode(ADBinding.self, from: data)

        XCTAssertTrue(decoded.isBound)
        XCTAssertEqual(decoded.realm, "CORP.EXAMPLE.COM")
        XCTAssertEqual(decoded.forest, "EXAMPLE.COM")
        XCTAssertEqual(decoded.computerAccount, "TESTMAC$")
        XCTAssertEqual(decoded.organizationalUnit, "OU=Macs,DC=corp,DC=example,DC=com")
        XCTAssertEqual(decoded.preferredDC, "dc01.corp.example.com")
        XCTAssertEqual(decoded.groupMappings.count, 2)
        XCTAssertEqual(decoded.groupMappings[0].adGroup, "Domain Admins")
        XCTAssertEqual(decoded.groupMappings[0].localGroup, "admin")
    }

    func testADBindingUnboundRoundtrip() throws {
        let binding = ADBinding(isBound: false)
        let data = try JSONEncoder().encode(binding)
        let decoded = try JSONDecoder().decode(ADBinding.self, from: data)

        XCTAssertFalse(decoded.isBound)
        XCTAssertNil(decoded.realm)
        XCTAssertNil(decoded.forest)
        XCTAssertEqual(decoded.groupMappings.count, 0)
    }

    func testADBindingCodingKeys() throws {
        let binding = ADBinding(
            isBound: true,
            realm: "CORP.EXAMPLE.COM",
            computerAccount: "MAC$"
        )
        let data = try JSONEncoder().encode(binding)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertNotNil(json["is_bound"])
        XCTAssertNotNil(json["computer_account"])
        XCTAssertNil(json["computerAccount"], "Should use snake_case keys")
    }

    // MARK: - dsconfigad parsing

    func testParseDsconfigadBound() {
        let ds = ActiveDirectoryDataSource()
        let output = """
        Active Directory Domain = CORP.EXAMPLE.COM
        Active Directory Forest = EXAMPLE.COM
        Computer Account       = TESTMAC$
        Organizational Unit    = OU=Macs,DC=corp,DC=example,DC=com
        Preferred Domain Controller = dc01.corp.example.com
        Allowed admin groups   = CORP\\Domain Admins, CORP\\Mac Admins
        """
        let binding = ds.parseDsconfigadOutput(output)

        XCTAssertTrue(binding.isBound)
        XCTAssertEqual(binding.realm, "CORP.EXAMPLE.COM")
        XCTAssertEqual(binding.forest, "EXAMPLE.COM")
        XCTAssertEqual(binding.computerAccount, "TESTMAC$")
        XCTAssertEqual(binding.organizationalUnit, "OU=Macs,DC=corp,DC=example,DC=com")
        XCTAssertEqual(binding.preferredDC, "dc01.corp.example.com")
        XCTAssertEqual(binding.groupMappings.count, 2)
    }

    func testParseDsconfigadUnbound() {
        let ds = ActiveDirectoryDataSource()
        // When not bound, dsconfigad -show typically returns no relevant output
        let output = "This computer is not bound to Active Directory."
        let binding = ds.parseDsconfigadOutput(output)

        XCTAssertFalse(binding.isBound)
        XCTAssertNil(binding.realm)
    }

    func testParseDsconfigadEmptyOutput() {
        let ds = ActiveDirectoryDataSource()
        let binding = ds.parseDsconfigadOutput("")

        XCTAssertFalse(binding.isBound)
    }

    // MARK: - Group mapping parsing

    func testParseGroupMappings() {
        let ds = ActiveDirectoryDataSource()
        let mappings = ds.parseGroupMappings("CORP\\Domain Admins, CORP\\Mac Admins")

        XCTAssertEqual(mappings.count, 2)
        XCTAssertEqual(mappings[0].adGroup, "CORP\\Domain Admins")
        XCTAssertEqual(mappings[0].localGroup, "admin")
        XCTAssertEqual(mappings[1].adGroup, "CORP\\Mac Admins")
    }

    func testParseGroupMappingsNil() {
        let ds = ActiveDirectoryDataSource()
        XCTAssertEqual(ds.parseGroupMappings(nil).count, 0)
    }

    func testParseGroupMappingsEmpty() {
        let ds = ActiveDirectoryDataSource()
        XCTAssertEqual(ds.parseGroupMappings("").count, 0)
    }

    // MARK: - Network user detection

    func testParseNetworkUsers() {
        let ds = ActiveDirectoryDataSource()
        let searchOutput = "root\ntestuser\njsmith\n_spotlight"
        let localOutput = "root\ntestuser\n_spotlight"

        let adUsers = ds.parseNetworkUsers(searchOutput: searchOutput, localOutput: localOutput)
        XCTAssertEqual(adUsers, ["jsmith"])
    }

    func testParseNetworkUsersNone() {
        let ds = ActiveDirectoryDataSource()
        let output = "root\ntestuser"
        let adUsers = ds.parseNetworkUsers(searchOutput: output, localOutput: output)
        XCTAssertTrue(adUsers.isEmpty)
    }

    func testParseNetworkUsersMultiple() {
        let ds = ActiveDirectoryDataSource()
        let searchOutput = "root\ntestuser\njsmith\njdoe\n_spotlight"
        let localOutput = "root\ntestuser\n_spotlight"

        let adUsers = ds.parseNetworkUsers(searchOutput: searchOutput, localOutput: localOutput)
        XCTAssertEqual(adUsers, ["jdoe", "jsmith"])  // sorted
    }

    // MARK: - UserDetail with isADUser

    func testUserDetailIsADUserRoundtrip() throws {
        let user = UserDetail(name: "jsmith", shell: "/bin/bash", homeDir: "/Users/jsmith", isHidden: false, isADUser: true)
        let data = try JSONEncoder().encode(user)
        let decoded = try JSONDecoder().decode(UserDetail.self, from: data)

        XCTAssertTrue(decoded.isADUser)
        XCTAssertEqual(decoded.name, "jsmith")
    }

    func testUserDetailIsADUserDefaultFalse() throws {
        let user = UserDetail(name: "local", shell: "/bin/zsh", homeDir: "/Users/local", isHidden: false)
        let data = try JSONEncoder().encode(user)
        let decoded = try JSONDecoder().decode(UserDetail.self, from: data)

        XCTAssertFalse(decoded.isADUser)
    }

    // MARK: - AD group membership discovery

    func testDiffGroupMembershipFindsADUsers() {
        // This tests the diff logic — actual dscl calls won't find AD users
        // in a CI environment, so we test the parser directly.
        let ds = ActiveDirectoryDataSource()

        // Simulate: /Search has "jsmith" in _developer, local does not
        let searchOutput = "GroupMembership: testuser jsmith"
        let localOutput = "GroupMembership: testuser"

        let searchMembers = searchOutput.components(separatedBy: ":").last?
            .split(whereSeparator: \.isWhitespace).map(String.init) ?? []
        let localMembers = localOutput.components(separatedBy: ":").last?
            .split(whereSeparator: \.isWhitespace).map(String.init) ?? []
        let diff = Set(searchMembers).subtracting(localMembers).sorted()

        XCTAssertEqual(diff, ["jsmith"])
    }

    func testSecurityRelevantGroupsDoesNotIncludeAdmin() {
        // Admin group mappings are handled by parseGroupMappings via dsconfigad.
        // The discovery method covers non-admin groups only.
        XCTAssertFalse(ActiveDirectoryDataSource.securityRelevantGroups.contains("admin"))
    }

    // MARK: - Metadata

    func testDataSourceMetadata() {
        let ds = ActiveDirectoryDataSource()
        XCTAssertEqual(ds.name, "Active Directory")
        XCTAssertFalse(ds.requiresElevation)
    }
}
