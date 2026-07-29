import Foundation
import XCTest
@testable import RootstockBlueFX

/// Drives the shared FX helper entry points (not re-implementations).
final class ParserHelpersTests: XCTestCase {
    func testStringishAndBoolish() {
        XCTAssertEqual(stringish("ok"), "ok")
        XCTAssertEqual(stringish(NSNumber(value: 42)), "42")
        XCTAssertNil(stringish(nil))
        XCTAssertEqual(stringValue("alias"), "alias")
        XCTAssertEqual(boolish(true), true)
        XCTAssertEqual(boolish("YES"), true)
        XCTAssertEqual(boolish("0"), false)
        XCTAssertNil(boolish("maybe"))
    }

    func testParseDateISO8601() {
        let d = parseDate("2024-06-01T12:00:00Z")
        XCTAssertNotNil(d)
        XCTAssertEqual(parseDate(d as Any), d)
    }

    func testInferUserFromPathAndURL() {
        XCTAssertEqual(inferUser(from: "/Volumes/img/Users/alice/Library/foo"), "alice")
        XCTAssertNil(inferUser(from: "/Volumes/img/Users/Shared/Library/foo"))
        let url = URL(fileURLWithPath: "/tmp/Users/bob/Library/x")
        XCTAssertEqual(inferUser(from: url), "bob")
    }

    func testArtifactIOJSONAndPlistRoundTrip() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("parser-helpers-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let jsonURL = dir.appendingPathComponent("items.json")
        let payload: [String: Any] = [
            "items": [
                ["name": "a", "enabled": true],
                ["name": "b", "enabled": false],
            ],
        ]
        let data = try JSONSerialization.data(withJSONObject: payload)
        try data.write(to: jsonURL)

        let entries = ArtifactIO.jsonDictionaryEntries(
            contentsOf: jsonURL,
            nestedKeys: ["items", "providers"],
            identityKeys: ["name"]
        )
        XCTAssertEqual(entries.count, 2)
        XCTAssertEqual(stringish(entries[0]["name"]), "a")
        XCTAssertEqual(boolish(entries[0]["enabled"]), true)

        let single = dir.appendingPathComponent("one.json")
        try JSONSerialization.data(withJSONObject: ["name": "solo"]).write(to: single)
        let one = ArtifactIO.jsonDictionaryEntries(
            contentsOf: single,
            nestedKeys: ["items"],
            identityKeys: ["name"]
        )
        XCTAssertEqual(one.count, 1)

        let jsonl = dir.appendingPathComponent("rows.jsonl")
        try "# comment\n{\"k\":\"v\"}\n\n".write(to: jsonl, atomically: true, encoding: .utf8)
        let rows = ArtifactIO.jsonlDictionaries(contentsOf: jsonl)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(stringish(rows[0]["k"]), "v")

        let plistURL = dir.appendingPathComponent("prefs.plist")
        let plistData = try PropertyListSerialization.data(
            fromPropertyList: ["ProductVersion": "15.0", "Flag": true],
            format: .xml,
            options: 0
        )
        try plistData.write(to: plistURL)
        let dict = ArtifactIO.plistDict(contentsOf: plistURL)
        XCTAssertEqual(stringish(dict?["ProductVersion"]), "15.0")

        let both = ArtifactIO.jsonOrPlistDict(contentsOf: plistURL)
        XCTAssertEqual(stringish(both?["ProductVersion"]), "15.0")
    }

    func testPathDeduper() {
        var d = PathDeduper()
        let a = URL(fileURLWithPath: "/tmp/Users/x/a.json")
        let b = URL(fileURLWithPath: "/tmp/Users/x/./a.json")
        XCTAssertTrue(d.insert(a))
        XCTAssertFalse(d.insert(b))
        XCTAssertTrue(d.contains(a))
    }

    func testStringArraySharedHelper() {
        XCTAssertEqual(stringArray(["a", "b"]), ["a", "b"])
        XCTAssertEqual(stringArray([1, "x"] as [Any]), ["1", "x"])
        XCTAssertEqual(stringArray("one, two"), ["one", "two"])
        XCTAssertEqual(stringArray(nil), [])
    }

    func testPlistObjectAndArray() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("plist-array-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let arr: [[String: Any]] = [["name": "pkg1"], ["name": "pkg2"]]
        let data = try PropertyListSerialization.data(fromPropertyList: arr, format: .xml, options: 0)
        let url = dir.appendingPathComponent("history.plist")
        try data.write(to: url)

        let loaded = ArtifactIO.plistArray(contentsOf: url)
        XCTAssertEqual(loaded?.count, 2)
        XCTAssertEqual(stringish(loaded?[0]["name"]), "pkg1")

        let obj = ArtifactIO.plistObject(from: data)
        XCTAssertNotNil(obj as? [[String: Any]])
        let entries = ArtifactIO.plistDictionaryEntries(from: data)
        XCTAssertEqual(entries.count, 2)
    }
}
