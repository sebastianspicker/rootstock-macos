import XCTest
import Foundation
@testable import FileACLs
import Models

final class FileACLTests: XCTestCase {

    func testFileACLNodeType() {
        let acl = FileACL(
            path: "/etc/sudoers",
            owner: "root",
            group: "wheel",
            mode: "440",
            isSipProtected: false,
            isWritableByNonRoot: false,
            category: "sudoers"
        )
        XCTAssertEqual(acl.nodeType, "FileACL")
    }

    func testFileACLJSONEncoding() throws {
        let acl = FileACL(
            path: "/Library/Application Support/com.apple.TCC/TCC.db",
            owner: "root",
            group: "admin",
            mode: "644",
            aclEntries: ["user:admin allow read,write"],
            isSipProtected: false,
            isWritableByNonRoot: true,
            category: "tcc_database"
        )
        let data = try JSONEncoder().encode(acl)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertEqual(json["path"] as? String, "/Library/Application Support/com.apple.TCC/TCC.db")
        XCTAssertEqual(json["owner"] as? String, "root")
        XCTAssertEqual(json["is_writable_by_non_root"] as? Bool, true)
        XCTAssertEqual(json["category"] as? String, "tcc_database")

        let entries = json["acl_entries"] as? [String]
        XCTAssertEqual(entries?.count, 1)
    }

    func testExpandTilde() {
        let expanded = FileACLDataSource.expandTilde("~/Library/test")
        XCTAssertFalse(expanded.hasPrefix("~"))
        XCTAssertTrue(expanded.contains("Library/test"))
    }

    func testIsSIPProtected() {
        XCTAssertTrue(FileACLDataSource.isSIPProtected("/System/Library/test"))
        XCTAssertTrue(FileACLDataSource.isSIPProtected("/usr/bin/ls"))
        XCTAssertFalse(FileACLDataSource.isSIPProtected("/Library/LaunchDaemons/test.plist"))
        XCTAssertFalse(FileACLDataSource.isSIPProtected("/etc/sudoers"))
    }

    func testCheckWritableByNonRootWorldWritable() {
        // Mode 666 = rw-rw-rw- → world-writable
        XCTAssertTrue(FileACLDataSource.checkWritableByNonRoot(posixPerms: 0o666, owner: "root", aclEntries: []))
    }

    func testCheckWritableByNonRootOwnerNotRoot() {
        // Mode 644 owned by non-root → writable by non-root owner
        XCTAssertTrue(FileACLDataSource.checkWritableByNonRoot(posixPerms: 0o644, owner: "admin", aclEntries: []))
    }

    func testCheckWritableByNonRootRootOwned() {
        // Mode 644 owned by root → not writable by non-root
        XCTAssertFalse(FileACLDataSource.checkWritableByNonRoot(posixPerms: 0o644, owner: "root", aclEntries: []))
    }

    func testCheckWritableByNonRootACLGrant() {
        // Root-owned but ACL grants write
        XCTAssertTrue(FileACLDataSource.checkWritableByNonRoot(
            posixPerms: 0o644, owner: "root",
            aclEntries: ["user:admin allow read,write"]
        ))
    }

    func testParseACLOutput() {
        let output = """
        -rw-r--r--+ 1 root  wheel  1234 Mar 18 10:00 /etc/test
         0: user:admin allow read,write,execute
         1: group:staff deny write
        """
        let entries = FileACLDataSource.parseACLOutput(output)
        XCTAssertEqual(entries.count, 2)
        XCTAssertTrue(entries[0].contains("allow read,write,execute"))
        XCTAssertTrue(entries[1].contains("deny write"))
    }

    func testParseACLOutputNoEntries() {
        let output = "-rw-r--r--  1 root  wheel  1234 Mar 18 10:00 /etc/test\n"
        let entries = FileACLDataSource.parseACLOutput(output)
        XCTAssertTrue(entries.isEmpty)
    }

    func testDataSourceMetadata() {
        let ds = FileACLDataSource()
        XCTAssertEqual(ds.name, "File ACLs")
        XCTAssertFalse(ds.requiresElevation)
    }

    func testDataSourceCollectsWithoutCrash() async {
        let ds = FileACLDataSource()
        let result = await ds.collect()
        XCTAssertGreaterThanOrEqual(result.nodes.count, 0)
    }
}
