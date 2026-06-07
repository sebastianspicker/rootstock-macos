import Foundation

enum RootstockModuleID: String, CaseIterable {
    case tcc
    case entitlements
    case codeSigning = "codesigning"
    case xpc
    case persistence
    case keychain
    case mdm
    case groups
    case remoteAccess = "remoteaccess"
    case firewall
    case loginSessions = "loginsessions"
    case authorizationDB = "authorizationdb"
    case authorizationPlugins = "authplugins"
    case systemExtensions = "systemextensions"
    case sudoers
    case processSnapshot = "processsnapshot"
    case fileACLs = "fileacls"
    case shellHooks = "shellhooks"
    case physicalSecurity = "physicalsecurity"
    case activeDirectory = "activedirectory"
    case kerberos
    case sandbox
    case quarantine
}

enum RootstockModuleConfigError: Error, CustomStringConvertible {
    case unknownModules([String])
    case missingPrerequisites([String])

    var description: String {
        switch self {
        case .unknownModules(let modules):
            return "Unknown module(s): \(modules.joined(separator: ", "))"
        case .missingPrerequisites(let messages):
            return messages.joined(separator: "; ")
        }
    }
}

extension ScanOrchestrator {
    struct ModuleConfig {
        private let selectedModules: Set<RootstockModuleID>

        static let moduleNames = RootstockModuleID.allCases.map(\.rawValue)
        static let supportedModuleNames = Set(["all"] + moduleNames)
        static let supportedModuleHelp = moduleNames.joined(separator: ", ")

        var selectedModuleNames: Set<String> {
            Set(selectedModules.map(\.rawValue))
        }

        func includes(_ module: RootstockModuleID) -> Bool {
            selectedModules.contains(module)
        }

        /// Parse a comma-separated module string or "all".
        static func from(_ moduleString: String) throws -> ModuleConfig {
            let parts = Set(
                moduleString
                    .split(separator: ",")
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }
            )
            let unknown = parts.subtracting(supportedModuleNames)
            if !unknown.isEmpty {
                throw RootstockModuleConfigError.unknownModules(unknown.sorted())
            }
            let all = parts.contains("all")
            let selected: Set<RootstockModuleID>
            if all {
                selected = Set(RootstockModuleID.allCases)
            } else {
                selected = Set(parts.compactMap(RootstockModuleID.init(rawValue:)))
            }
            if !selected.contains(.entitlements) {
                let enrichmentModules = [RootstockModuleID.sandbox, .quarantine].filter { selected.contains($0) }
                if !enrichmentModules.isEmpty {
                    let messages = enrichmentModules.map {
                        "Module '\($0.rawValue)' requires module 'entitlements'"
                    }
                    throw RootstockModuleConfigError.missingPrerequisites(messages)
                }
            }
            return ModuleConfig(selectedModules: selected)
        }
    }
}
