/// Offline forensic parser: UsersParser - fixture-backed IR events (no secret export).
import Foundation
import RootstockBlueCore

public struct UsersParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "USERS",
        tier: .tier1,
        description: "Local user account plists (dslocal-style)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        let userDirs = [
            "var/db/dslocal/nodes/Default/users",
            "private/var/db/dslocal/nodes/Default/users",
        ]
        var plists: [URL] = []
        for dir in userDirs {
            let url = root.file(dir)
            if let items = try? FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil) {
                plists.append(contentsOf: items.filter { $0.pathExtension == "plist" })
            }
        }
        // Also pick up any users/*.plist under the tree
        plists.append(contentsOf: root.enumerate {
            $0.pathExtension == "plist" && $0.path.contains("/users/")
        })

        var seen = PathDeduper()
        var events: [EventEnvelope] = []
        for plist in plists {
            if !seen.insert(plist) { continue }
            if let e = parseUserPlist(at: plist) {
                events.append(e)
            }
        }
        return events
    }

    private func parseUserPlist(at url: URL) -> EventEnvelope? {
        guard let dict = ArtifactIO.plistDict(contentsOf: url) else { return nil }

        let name = firstString(dict["name"]) ?? url.deletingPathExtension().lastPathComponent
        let uid = firstString(dict["uid"]) ?? ""
        let home = firstString(dict["home"]) ?? ""
        let shell = firstString(dict["shell"]) ?? ""
        let realname = firstString(dict["realname"]) ?? name

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "user.account",
                label: "USERS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [.user(name: name)],
                properties: [
                FieldTaxonomy.userName: name,
                "user.uid": uid,
                "user.home": home,
                "user.shell": shell,
                "user.realname": realname,
                "user.plist_path": url.path,
                FieldTaxonomy.eventType: "user.account",
            ],
                provenance: url.path,
                confidence: 0.9
            )
        )
    }

    private func firstString(_ any: Any?) -> String? {
        if let s = any as? String { return s }
        if let a = any as? [Any], let s = a.first as? String { return s }
        if let a = any as? [String], let s = a.first { return s }
        return nil
    }
}
