import Foundation
import RootstockCore

/// Developer toolchain dual-use surface (path heuristics only).
///
/// Research basis: PEASS / red-team "dev tools as LOOBins" inventories; Xcode / CLT presence
/// as dual-use compile-and-sign surface.
/// Safety and behavior: typed `DeveloperToolchainState`; presence of clang/swift/codesign only,
/// never runs compilers, never codesigns payloads, never harvests certs/keychains.
public struct DeveloperToolchainCollector: Collector {
    public static let id = "collect.developer_toolchain"
    public static let cost: CollectorCost = .low

    private static let xcodePaths: [String] = [
        "/Applications/Xcode.app",
        "/Applications/Xcode-beta.app",
    ]

    private static let cltPaths: [String] = [
        "/Library/Developer/CommandLineTools",
        "/Library/Developer/CommandLineTools/usr/bin/clang",
    ]

    /// Dual-use toolchain binaries (presence = inventory; not execution).
    private static let dualUseBinaryProbes: [(name: String, path: String)] = [
        ("clang", "/usr/bin/clang"),
        ("clang++", "/usr/bin/clang++"),
        ("swift", "/usr/bin/swift"),
        ("swiftc", "/usr/bin/swiftc"),
        ("codesign", "/usr/bin/codesign"),
        ("ld", "/usr/bin/ld"),
        ("dsymutil", "/usr/bin/dsymutil"),
        ("otool", "/usr/bin/otool"),
        ("nm", "/usr/bin/nm"),
        ("lipo", "/usr/bin/lipo"),
        ("install_name_tool", "/usr/bin/install_name_tool"),
        ("xcrun", "/usr/bin/xcrun"),
        ("xcodebuild", "/usr/bin/xcodebuild"),
        ("xcode-select", "/usr/bin/xcode-select"),
        ("llvm-codesign", "/usr/bin/llvm-codesign"),
        ("llvm-objcopy", "/usr/bin/llvm-objcopy"),
        ("nasm", "/usr/local/bin/nasm"),
        ("gcc", "/usr/bin/gcc"),
        ("make", "/usr/bin/make"),
        ("git", "/usr/bin/git"),
        ("python3", "/usr/bin/python3"),
    ]

    private static let extraToolchainPaths: [String] = [
        "/Applications/Xcode.app/Contents/Developer",
        "/Applications/Xcode.app/Contents/Developer/Toolchains",
        "/Library/Developer/CommandLineTools/SDKs",
        "/opt/homebrew/bin/clang",
        "/usr/local/bin/clang",
        "/opt/homebrew/opt/llvm/bin/clang",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        var notes = ["Developer toolchain dual-use inventory - path presence only; no compile/sign/run"]
        let xcodePresent = observed(Self.xcodePaths, presentNote: "Xcode present", absentNote: "Xcode.app not observed under /Applications", notes: &notes)
        let commandLineToolsPresent = observed(Self.cltPaths, presentNote: "CommandLineTools path", absentNote: "CommandLineTools not observed at catalog paths", notes: &notes)
        let toolchainPaths = toolchainPaths(notes: &notes)
        let dualUseBinaries = dualUseBinaries(notes: &notes)
        var state = CollectedState()
        state.developerToolchain = DeveloperToolchainState(xcodePresent: xcodePresent, commandLineToolsPresent: commandLineToolsPresent, toolchainPaths: toolchainPaths, dualUseBinaries: dualUseBinaries, notes: notes)
        state.collectorNotes[Self.id] = "xcode=\(xcodePresent.map(String.init(describing:)) ?? "nil") " + "clt=\(commandLineToolsPresent.map(String.init(describing:)) ?? "nil") " + "toolchainPaths=\(toolchainPaths.count) " + "dualUse=\(dualUseBinaries.count)"
        return state
    }


    private func observed(_ paths: [String], presentNote: String, absentNote: String, notes: inout [String]) -> Bool? {
        let matches = paths.filter { FileManager.default.fileExists(atPath: $0) }
        notes.append(contentsOf: matches.map { "\(presentNote): \($0)" })
        if matches.isEmpty {
            notes.append(absentNote)
            return false
        }
        return true
    }

    private func toolchainPaths(notes: inout [String]) -> [String] {
        var paths = (Self.xcodePaths + Self.cltPaths + Self.extraToolchainPaths).filter {
            FileManager.default.fileExists(atPath: $0)
        }
        for path in userToolchainHints() where FileManager.default.fileExists(atPath: path) {
            paths.append(path)
            notes.append("user_toolchain: \(path)")
        }
        return Array(Set(paths)).sorted()
    }

    private func dualUseBinaries(notes: inout [String]) -> [String] {
        let paths = Self.dualUseBinaryProbes.compactMap { probe -> String? in
            guard FileManager.default.fileExists(atPath: probe.path) else { return nil }
            notes.append("dual_use: \(probe.name) path=\(probe.path)")
            return probe.path
        }
        return Array(Set(paths)).sorted()
    }

    private func userToolchainHints() -> [String] {
        let home = NSHomeDirectory()
        return ["\(home)/.swiftpm", "\(home)/Library/Developer/Xcode", "\(home)/Library/Developer/Toolchains"]
    }
}
