import XCTest
import Foundation
@testable import Models
@testable import KerberosArtifacts

final class KerberosArtifactTests: XCTestCase {

    // MARK: - Model roundtrip

    func testCcacheRoundtrip() throws {
        let artifact = KerberosArtifact(
            path: "/tmp/krb5cc_501",
            artifactType: .ccache,
            owner: "testuser",
            group: "staff",
            mode: "600",
            modificationTime: "2026-03-18T10:00:00Z",
            principalHint: "testuser",
            isReadable: true,
            isWorldReadable: false
        )
        let data = try JSONEncoder().encode(artifact)
        let decoded = try JSONDecoder().decode(KerberosArtifact.self, from: data)

        XCTAssertEqual(decoded.path, "/tmp/krb5cc_501")
        XCTAssertEqual(decoded.artifactType, .ccache)
        XCTAssertEqual(decoded.owner, "testuser")
        XCTAssertEqual(decoded.group, "staff")
        XCTAssertEqual(decoded.mode, "600")
        XCTAssertEqual(decoded.principalHint, "testuser")
        XCTAssertTrue(decoded.isReadable)
        XCTAssertFalse(decoded.isWorldReadable)
    }

    func testKeytabRoundtrip() throws {
        let artifact = KerberosArtifact(
            path: "/etc/krb5.keytab",
            artifactType: .keytab,
            owner: "root",
            group: "wheel",
            mode: "600",
            isReadable: false,
            isWorldReadable: false
        )
        let data = try JSONEncoder().encode(artifact)
        let decoded = try JSONDecoder().decode(KerberosArtifact.self, from: data)

        XCTAssertEqual(decoded.artifactType, .keytab)
        XCTAssertEqual(decoded.path, "/etc/krb5.keytab")
        XCTAssertNil(decoded.principalHint)
    }

    func testConfigRoundtrip() throws {
        let artifact = KerberosArtifact(
            path: "/etc/krb5.conf",
            artifactType: .config,
            owner: "root",
            group: "wheel",
            mode: "644",
            isReadable: true,
            isWorldReadable: true
        )
        let data = try JSONEncoder().encode(artifact)
        let decoded = try JSONDecoder().decode(KerberosArtifact.self, from: data)

        XCTAssertEqual(decoded.artifactType, .config)
        XCTAssertTrue(decoded.isWorldReadable)
    }

    func testCodingKeys() throws {
        let artifact = KerberosArtifact(
            path: "/tmp/krb5cc_501",
            artifactType: .ccache,
            principalHint: "user",
            isReadable: true,
            isWorldReadable: false
        )
        let data = try JSONEncoder().encode(artifact)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertNotNil(json["artifact_type"])
        XCTAssertNotNil(json["principal_hint"])
        XCTAssertNotNil(json["is_readable"])
        XCTAssertNotNil(json["is_world_readable"])
        XCTAssertNotNil(json["is_group_readable"])
        XCTAssertNil(json["artifactType"], "Should use snake_case keys")
    }

    func testConfigWithParsedFieldsRoundtrip() throws {
        let artifact = KerberosArtifact(
            path: "/etc/krb5.conf",
            artifactType: .config,
            owner: "root",
            group: "wheel",
            mode: "644",
            isReadable: true,
            isWorldReadable: true,
            isGroupReadable: true,
            defaultRealm: "CORP.EXAMPLE.COM",
            permittedEncTypes: ["aes256-cts-hmac-sha1-96", "rc4-hmac"],
            realmNames: ["CORP.EXAMPLE.COM", "DEV.EXAMPLE.COM"],
            isForwardable: true
        )
        let data = try JSONEncoder().encode(artifact)
        let decoded = try JSONDecoder().decode(KerberosArtifact.self, from: data)

        XCTAssertEqual(decoded.defaultRealm, "CORP.EXAMPLE.COM")
        XCTAssertEqual(decoded.permittedEncTypes, ["aes256-cts-hmac-sha1-96", "rc4-hmac"])
        XCTAssertEqual(decoded.realmNames?.count, 2)
        XCTAssertTrue(decoded.isForwardable ?? false)
        XCTAssertTrue(decoded.isGroupReadable)
    }

    func testConfigFieldsCodingKeys() throws {
        let artifact = KerberosArtifact(
            path: "/etc/krb5.conf",
            artifactType: .config,
            defaultRealm: "TEST.COM",
            permittedEncTypes: ["aes256-cts-hmac-sha1-96"]
        )
        let data = try JSONEncoder().encode(artifact)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertNotNil(json["default_realm"])
        XCTAssertNotNil(json["permitted_enc_types"])
        XCTAssertNil(json["defaultRealm"], "Should use snake_case keys")
    }

    // MARK: - Principal inference

    func testInferPrincipalFromFilename() {
        let ds = KerberosArtifactDataSource()

        // krb5cc_0 → root (uid 0)
        let root = ds.inferPrincipalFromFilename("krb5cc_0")
        XCTAssertEqual(root, "root")

        // Invalid filename
        let invalid = ds.inferPrincipalFromFilename("notakrbfile")
        XCTAssertNil(invalid)

        // Non-numeric uid
        let nonNumeric = ds.inferPrincipalFromFilename("krb5cc_abc")
        XCTAssertNil(nonNumeric)
    }

    // MARK: - World readable check

    func testIsWorldReadable() {
        // 644 = rw-r--r-- → others have read
        XCTAssertTrue(KerberosArtifactDataSource.isWorldReadable(mode: 0o644))

        // 600 = rw------- → others have no access
        XCTAssertFalse(KerberosArtifactDataSource.isWorldReadable(mode: 0o600))

        // 755 = rwxr-xr-x → others have read+execute
        XCTAssertTrue(KerberosArtifactDataSource.isWorldReadable(mode: 0o755))

        // 700 = rwx------ → no others access
        XCTAssertFalse(KerberosArtifactDataSource.isWorldReadable(mode: 0o700))

        // nil mode
        XCTAssertFalse(KerberosArtifactDataSource.isWorldReadable(mode: nil))
    }

    // MARK: - Group readable check

    func testIsGroupReadable() {
        // 640 = rw-r----- → group has read
        XCTAssertTrue(KerberosArtifactDataSource.isGroupReadable(mode: 0o640))

        // 600 = rw------- → no group access
        XCTAssertFalse(KerberosArtifactDataSource.isGroupReadable(mode: 0o600))

        // 644 = rw-r--r-- → group has read
        XCTAssertTrue(KerberosArtifactDataSource.isGroupReadable(mode: 0o644))

        // 700 = rwx------ → no group access
        XCTAssertFalse(KerberosArtifactDataSource.isGroupReadable(mode: 0o700))

        // 750 = rwxr-x--- → group has read+execute
        XCTAssertTrue(KerberosArtifactDataSource.isGroupReadable(mode: 0o750))

        // nil mode
        XCTAssertFalse(KerberosArtifactDataSource.isGroupReadable(mode: nil))
    }

    // MARK: - krb5.conf parsing

    func testParseKrb5ConfBasic() {
        let ds = KerberosArtifactDataSource()
        let contents = """
        [libdefaults]
            default_realm = CORP.EXAMPLE.COM
            forwardable = true
            permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

        [realms]
            CORP.EXAMPLE.COM = {
                kdc = kdc.corp.example.com
                admin_server = kadmin.corp.example.com
            }

        [domain_realm]
            .corp.example.com = CORP.EXAMPLE.COM
        """
        let config = ds.parseKrb5ConfContents(contents)

        XCTAssertEqual(config.defaultRealm, "CORP.EXAMPLE.COM")
        XCTAssertTrue(config.isForwardable ?? false)
        XCTAssertEqual(config.permittedEncTypes, ["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"])
        XCTAssertEqual(config.realmNames, ["CORP.EXAMPLE.COM"])
    }

    func testParseKrb5ConfWeakEncryption() {
        let ds = KerberosArtifactDataSource()
        let contents = """
        [libdefaults]
            default_realm = LEGACY.COM
            permitted_enctypes = des-cbc-crc rc4-hmac aes256-cts-hmac-sha1-96
        """
        let config = ds.parseKrb5ConfContents(contents)

        XCTAssertEqual(config.permittedEncTypes?.count, 3)
        XCTAssertTrue(config.permittedEncTypes?.contains("des-cbc-crc") ?? false)
        XCTAssertTrue(config.permittedEncTypes?.contains("rc4-hmac") ?? false)
    }

    func testParseKrb5ConfMultipleRealms() {
        let ds = KerberosArtifactDataSource()
        let contents = """
        [realms]
            CORP.EXAMPLE.COM = {
                kdc = kdc1.corp.example.com
            }
            DEV.EXAMPLE.COM = {
                kdc = kdc1.dev.example.com
            }
        """
        let config = ds.parseKrb5ConfContents(contents)

        XCTAssertEqual(config.realmNames?.count, 2)
        XCTAssertTrue(config.realmNames?.contains("CORP.EXAMPLE.COM") ?? false)
        XCTAssertTrue(config.realmNames?.contains("DEV.EXAMPLE.COM") ?? false)
    }

    func testParseKrb5ConfEmpty() {
        let ds = KerberosArtifactDataSource()
        let config = ds.parseKrb5ConfContents("")

        XCTAssertNil(config.defaultRealm)
        XCTAssertNil(config.permittedEncTypes)
        XCTAssertNil(config.realmNames)
        XCTAssertNil(config.isForwardable)
    }

    func testParseKrb5ConfCommentsIgnored() {
        let ds = KerberosArtifactDataSource()
        let contents = """
        # This is a comment
        [libdefaults]
            # Another comment
            default_realm = TEST.COM
            ; semicolon comment
            forwardable = false
        """
        let config = ds.parseKrb5ConfContents(contents)

        XCTAssertEqual(config.defaultRealm, "TEST.COM")
        XCTAssertFalse(config.isForwardable ?? true)
    }

    // MARK: - Metadata

    func testDataSourceMetadata() {
        let ds = KerberosArtifactDataSource()
        XCTAssertEqual(ds.name, "Kerberos Artifacts")
        XCTAssertFalse(ds.requiresElevation)
    }

    // MARK: - GraphNode conformance

    func testNodeType() {
        let artifact = KerberosArtifact(
            path: "/tmp/krb5cc_501",
            artifactType: .ccache
        )
        XCTAssertEqual(artifact.nodeType, "KerberosArtifact")
    }
}
