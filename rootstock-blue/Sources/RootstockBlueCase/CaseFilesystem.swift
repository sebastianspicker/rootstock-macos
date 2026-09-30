import Darwin
import Foundation
import RootstockBlueCore

/// Non-following filesystem checks used to keep a case package self-contained.
/// URL resource values can follow links on some paths, so package validation uses
/// `lstat` whenever the on-disk object type is part of the case contract.
enum CaseFilesystem {
    enum NodeType {
        case regularFile
        case directory
        case symbolicLink
        case other
    }

    static func nodeType(at url: URL, label: String) throws -> NodeType {
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            throw RootstockBlueError.invalidCasePackage("cannot lstat \(label)")
        }
        switch info.st_mode & S_IFMT {
        case S_IFREG: return .regularFile
        case S_IFDIR: return .directory
        case S_IFLNK: return .symbolicLink
        default: return .other
        }
    }

    static func requireRegularFile(at url: URL, label: String) throws {
        guard try nodeType(at: url, label: label) == .regularFile else {
            throw RootstockBlueError.invalidCasePackage("\(label) must be a real regular file")
        }
    }

    static func requireRegularFile(descriptor: Int32, label: String) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw RootstockBlueError.invalidCasePackage("\(label) must be an open regular file")
        }
    }

    static func openRegularFileNoFollow(at url: URL, label: String) throws -> Int32 {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW)
        guard descriptor >= 0 else {
            throw RootstockBlueError.invalidCasePackage("cannot open \(label) without following links")
        }
        do {
            try requireRegularFile(descriptor: descriptor, label: label)
            return descriptor
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    static func requireDirectory(at url: URL, label: String) throws {
        guard try nodeType(at: url, label: label) == .directory else {
            throw RootstockBlueError.invalidCasePackage("\(label) must be a real directory")
        }
    }
}
