/// IRHostTarget - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

/// Evidence target for `ir posture` / `ir harden`.
///
/// Blue is offline by default: the running Mac is read only when `--live` is passed.
public enum IRHostTarget: Equatable, Sendable {
    case offline(URL)
    case live

    public static func parse(_ args: [String], command: String) throws -> IRHostTarget {
        let live = args.contains("--live")
        guard let index = args.firstIndex(of: "--source") else {
            guard live else {
                throw RootstockBlueError.io(
                    "\(command) requires --source <artifact-tree> for offline evidence, or --live to read this Mac"
                )
            }
            return .live
        }
        guard !live else {
            throw RootstockBlueError.io("\(command): pass either --source <artifact-tree> or --live, not both")
        }
        guard args.count > index + 1 else {
            throw RootstockBlueError.io("\(command): --source requires <artifact-tree>")
        }
        return .offline(URL(fileURLWithPath: args[index + 1]))
    }
}
