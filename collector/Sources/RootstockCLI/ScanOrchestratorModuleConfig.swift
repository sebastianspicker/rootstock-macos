import Foundation

/// Canonical command-line identifiers used for selection and collector dispatch.
enum RootstockModuleID: String, CaseIterable, Sendable {
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
    /// Normalized module selection with prerequisite validation.
    ///
    /// Sandbox and quarantine are application enrichments, so they require the
    /// entitlement discovery pass that supplies their application snapshot.
    struct ModuleConfig: Sendable {
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

        /// Parses, deduplicates, and validates a comma-separated list or `all`.
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
