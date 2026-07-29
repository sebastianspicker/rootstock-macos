import Foundation
import RootstockCore

/// Custom URL scheme / document-handler delivery posture (Wave-11).
///
/// Research basis: LS handlers / CFBundleURLTypes / open-url delivery research (2025–26 malware handlers).
/// Safety and behavior: typed path inventory only; never registers schemes or rewrites handlers.
public struct URLSchemeHandlerCollector: Collector {
    public static let id = "collect.url_scheme_handler"
    public static let cost: CollectorCost = .low

    private static let launchServicesPaths: [String] = [
        NSHomeDirectory() + "/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist",
        NSHomeDirectory() + "/Library/Preferences/com.apple.LaunchServices.plist",
        "/Library/Preferences/com.apple.LaunchServices",
        "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework",
    ]

    private static let documentHandlerPaths: [String] = [
        "/System/Library/CoreServices/LaunchServices.framework",
        "/usr/bin/open",
        "/usr/bin/osascript",
        "/System/Library/Frameworks/AppKit.framework",
    ]

    private static let openerBinaryPaths: [String] = [
        "/usr/bin/open",
        "/usr/bin/osascript",
        "/usr/bin/osacompile",
        "/bin/launchctl",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "URL scheme / document-handler surface: path presence only - never registers schemes or rewrites handlers",
        ]

        var ls: [String] = []
        for path in Self.launchServicesPaths where fm.fileExists(atPath: path) {
            ls.append(path)
            notes.append("launch_services: \(path)")
        }

        var urlTypes: [String] = []
        let sampleApps = [
            "/Applications/Safari.app/Contents/Info.plist",
            "/System/Applications/Utilities/Terminal.app/Contents/Info.plist",
            "/Applications/Google Chrome.app/Contents/Info.plist",
        ]
        for path in sampleApps where fm.fileExists(atPath: path) {
            urlTypes.append(path)
            notes.append("url_type_plist: \(path)")
        }

        var docs: [String] = []
        for path in Self.documentHandlerPaths where fm.fileExists(atPath: path) {
            docs.append(path)
            notes.append("document_handler: \(path)")
        }

        var openers: [String] = []
        for path in Self.openerBinaryPaths where fm.fileExists(atPath: path) {
            openers.append(path)
            notes.append("opener: \(path)")
        }

        ls = Array(Set(ls)).sorted()
        urlTypes = Array(Set(urlTypes)).sorted()
        docs = Array(Set(docs)).sorted()
        openers = Array(Set(openers)).sorted()

        let surface = !ls.isEmpty || urlTypes.count >= 1 || openers.count >= 2

        var state = CollectedState()
        state.urlSchemeHandler = URLSchemeHandlerState(
            launchServicesPaths: ls,
            urlTypePlistPaths: urlTypes,
            documentHandlerPaths: docs,
            openerBinaryPaths: openers,
            handlerSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "ls=\(ls.count) urlTypes=\(urlTypes.count) docs=\(docs.count) openers=\(openers.count) surface=\(surface)"
        return state
    }
}
