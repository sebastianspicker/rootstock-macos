import Foundation
import RootstockCore
import Security

/// Shared sampling of /Applications (+ optional extra paths) and codesign inspection.
enum AppSampleSupport {
    static let sampleLimit = 25

    /// Up to `sampleLimit` app bundle paths from /Applications, optionally unioned with extras.
    static func sampleAppBundlePaths(extraPaths: [String] = []) -> [String] {
        var ordered: [String] = []
        var seen = Set<String>()
        appendInstalledApps(to: &ordered, seen: &seen)
        appendExtraPaths(extraPaths, to: &ordered, seen: &seen)
        return Array(ordered.prefix(sampleLimit))
    }


    private static func appendInstalledApps(to ordered: inout [String], seen: inout Set<String>) {
        let root = URL(fileURLWithPath: "/Applications", isDirectory: true)
        guard let contents = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else { return }
        for app in contents.filter({ $0.pathExtension == "app" }).sorted(by: { $0.lastPathComponent.localizedCaseInsensitiveCompare($1.lastPathComponent) == .orderedAscending }) {
            appendUnique(app.path, to: &ordered, seen: &seen)
            if ordered.count >= sampleLimit { return }
        }
    }

    private static func appendExtraPaths(_ paths: [String], to ordered: inout [String], seen: inout Set<String>) {
        for path in paths where ordered.count < sampleLimit {
            let lower = path.lowercased()
            if lower.hasSuffix(".app") || lower.contains(".app/") {
                appendUnique(path.range(of: ".app", options: [.caseInsensitive]).map { String(path[..<$0.upperBound]) } ?? path, to: &ordered, seen: &seen)
            } else if FileManager.default.fileExists(atPath: path) {
                appendUnique(path, to: &ordered, seen: &seen)
            }
        }
    }

    private static func appendUnique(_ path: String, to ordered: inout [String], seen: inout Set<String>) {
        let standardized = (path as NSString).standardizingPath
        guard seen.insert(standardized).inserted else { return }
        ordered.append(standardized)
    }

    /// Main executable URL inside an .app, or the path itself for bare binaries.
    static func mainExecutablePath(for path: String) -> String? {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir) else { return nil }

        if path.lowercased().hasSuffix(".app") || isDir.boolValue {
            if let bundle = Bundle(path: path), let exe = bundle.executableURL?.path {
                return exe
            }
            let macos = URL(fileURLWithPath: path)
                .appendingPathComponent("Contents/MacOS", isDirectory: true)
            if let items = try? fm.contentsOfDirectory(atPath: macos.path),
               let first = items.first(where: { !$0.hasPrefix(".") })
            {
                return macos.appendingPathComponent(first).path
            }
            return nil
        }
        return path
    }

    static func inspectCodesign(path: String) -> CodesignSample {
        var staticCode: SecStaticCode?
        let cfURL = URL(fileURLWithPath: path) as CFURL
        let createStatus = SecStaticCodeCreateWithPath(cfURL, SecCSFlags(), &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            return CodesignSample(path: path, signature: .init(signed: false), notes: ["SecStaticCodeCreateWithPath failed: \(createStatus)"])
        }

        var infoCF: CFDictionary?
        // Signing info includes identifier, team, flags, entitlements.
        let copyStatus = SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &infoCF
        )
        guard copyStatus == errSecSuccess, let infoCF else {
            return CodesignSample(path: path, signature: .init(signed: false), notes: ["SecCodeCopySigningInformation failed: \(copyStatus)"])
        }

        let info = infoCF as NSDictionary
        let identifier = info[kSecCodeInfoIdentifier as String] as? String
        let team = info[kSecCodeInfoTeamIdentifier as String] as? String

        var hardened: Bool?
        if let flagsNum = info[kSecCodeInfoFlags as String] as? NSNumber {
            let flags = flagsNum.uint32Value
            // SecCodeSignatureRuntime - hardened runtime bit.
            hardened = (flags & UInt32(SecCodeSignatureFlags.runtime.rawValue)) != 0
        }

        let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
        func entBool(_ key: String) -> Bool? {
            guard let entitlements else { return nil }
            if let b = entitlements[key] as? Bool { return b }
            if let n = entitlements[key] as? NSNumber { return n.boolValue }
            return entitlements[key] != nil ? true : nil
        }

        return CodesignSample(path: path, signature: .init(signed: true, identifier: identifier, teamIdentifier: team, hardenedRuntime: hardened, getTaskAllow: entBool("com.apple.security.get-task-allow"), disableLibraryValidation: entBool("com.apple.security.cs.disable-library-validation"), allowDyldEnvironmentVariables: entBool("com.apple.security.cs.allow-dyld-environment-variables"), allowUnsignedExecutableMemory: entBool("com.apple.security.cs.allow-unsigned-executable-memory")), notes: [])
    }

    static func injectabilityHit(from sample: CodesignSample) -> InjectabilityHit {
        var flags: [String] = []
        if sample.getTaskAllow == true { flags.append("get-task-allow") }
        if sample.disableLibraryValidation == true { flags.append("disable-library-validation") }
        if sample.allowDyldEnvironmentVariables == true { flags.append("allow-dyld-environment-variables") }
        if sample.allowUnsignedExecutableMemory == true { flags.append("allow-unsigned-executable-memory") }
        if sample.hardenedRuntime == false { flags.append("no-hardened-runtime") }
        if sample.signed == false { flags.append("unsigned-or-unreadable") }

        return InjectabilityHit(
            path: sample.path,
            hardenedRuntime: sample.hardenedRuntime,
            getTaskAllow: sample.getTaskAllow,
            disableLibraryValidation: sample.disableLibraryValidation,
            allowDyldEnvironmentVariables: sample.allowDyldEnvironmentVariables,
            allowUnsignedExecutableMemory: sample.allowUnsignedExecutableMemory,
            riskFlags: flags,
            notes: sample.notes
        )
    }
}

// MARK: - Lightweight Mach-O weak dylib scan

enum MachOWeakDylibScanner {
    private static let mhMagic64: UInt32 = 0xFEED_FACF
    private static let mhCigam64: UInt32 = 0xCFFA_EDFE
    private static let fatMagic: UInt32 = 0xCAFE_BABE
    private static let fatCigam: UInt32 = 0xBEBA_FECA
    private static let lcLoadWeakDylib: UInt32 = 0x8000_0018

    /// Returns weak-dylib install names from a thin MH_MAGIC_64 (or first thin slice of a fat binary).
    static func weakDylibs(at path: String, maxBytes: Int = 2_000_000) -> (paths: [String], notes: [String]) {
        guard let handle = FileHandle(forReadingAtPath: path) else { return ([], ["unreadable"]) }
        defer { try? handle.close() }
        let result: Data?
        do {
            result = try handle.read(upToCount: maxBytes)
        } catch {
            return ([], ["read failed"])
        }
        guard let data = result else { return ([], ["empty"]) }
        guard data.count >= 32 else { return ([], ["too small"]) }
        return parse(data)
    }


    private static func parse(_ data: Data) -> (paths: [String], notes: [String]) {
        let magic = readU32(data, 0, bigEndian: false)
        if magic == fatMagic || magic == fatCigam { return parseFat64(data) }
        if magic == mhMagic64 || magic == mhCigam64 { return parseThin64(data) }
        return ([], ["not MH_MAGIC_64 (magic=\(String(magic, radix: 16)))"])
    }

    private static func parseFat64(_ data: Data) -> (paths: [String], notes: [String]) {
        let architectureCount = Int(readU32(data, 4, bigEndian: true))
        guard architectureCount > 0, data.count >= 28 else {
            return ([], ["fat header truncated"])
        }

        for index in 0..<min(architectureCount, 8) {
            let base = 8 + index * 20
            guard base + 20 <= data.count else { break }
            let offset = Int(readU32(data, base + 8, bigEndian: true))
            guard offset + 32 <= data.count else { continue }

            let slice = data.subdata(in: offset..<data.count)
            let magic = readU32(slice, 0, bigEndian: false)
            if magic == mhMagic64 || magic == mhCigam64 {
                return parseThin64(slice)
            }
        }
        return ([], ["no MH_MAGIC_64 fat slice found"])
    }

    private static func parseThin64(_ data: Data) -> (paths: [String], notes: [String]) {
        let swap = readU32(data, 0, bigEndian: false) == mhCigam64
        guard data.count >= 32 else { return ([], ["header truncated"]) }
        let ncmds = Int(readU32(data, 16, bigEndian: swap))
        let end = min(data.count, 32 + Int(readU32(data, 20, bigEndian: swap)))
        var offset = 32
        var weak: [String] = []
        for _ in 0..<ncmds {
            guard let command = command(data, offset: offset, end: end, swap: swap) else { break }
            if command.kind == lcLoadWeakDylib, let name = weakDylibName(data, offset: offset, commandSize: command.size, swap: swap) {
                weak.append(name)
            }
            offset += command.size
        }
        return (weak, [])
    }


    private struct LoadCommand {
        let kind: UInt32
        let size: Int
    }

    private static func command(_ data: Data, offset: Int, end: Int, swap: Bool) -> LoadCommand? {
        guard offset + 8 <= end else { return nil }
        let size = Int(readU32(data, offset + 4, bigEndian: swap))
        guard size >= 8, offset + size <= data.count else { return nil }
        return LoadCommand(kind: readU32(data, offset, bigEndian: swap), size: size)
    }

    private static func weakDylibName(_ data: Data, offset: Int, commandSize: Int, swap: Bool) -> String? {
        guard commandSize >= 24 else { return nil }
        let nameOffset = Int(readU32(data, offset + 8, bigEndian: swap))
        guard nameOffset > 0, offset + nameOffset < offset + commandSize else { return nil }
        return cString(data, start: offset + nameOffset, end: offset + commandSize)
    }

    private static func readU32(_ data: Data, _ offset: Int, bigEndian: Bool) -> UInt32 {
        let b0 = UInt32(data[offset])
        let b1 = UInt32(data[offset + 1])
        let b2 = UInt32(data[offset + 2])
        let b3 = UInt32(data[offset + 3])
        let le = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        if bigEndian {
            return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        }
        return le
    }

    private static func cString(_ data: Data, start: Int, end: Int) -> String? {
        var bytes: [UInt8] = []
        var i = start
        while i < end {
            let b = data[i]
            if b == 0 { break }
            bytes.append(b)
            i += 1
        }
        return bytes.isEmpty ? nil : String(bytes: bytes, encoding: .utf8)
    }
}
