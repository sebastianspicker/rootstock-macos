/// ImageSource - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public enum ImageSource: Sendable {
    case directory(URL)
    case dmg(URL)
    case logarchive(URL)
    case sparseimage(URL)
    case collectionZip(URL)

    public var url: URL {
        switch self {
        case .directory(let u), .dmg(let u), .logarchive(let u), .sparseimage(let u), .collectionZip(let u):
            return u.standardizedFileURL
        }
    }

    public static func infer(from url: URL) -> ImageSource {
        let standardized = url.standardizedFileURL
        let ext = standardized.pathExtension.lowercased()
        switch ext {
        case "dmg": return .dmg(standardized)
        case "logarchive": return .logarchive(standardized)
        case "sparseimage": return .sparseimage(standardized)
        case "zip": return .collectionZip(standardized)
        default:
            return .directory(standardized)
        }
    }
}
