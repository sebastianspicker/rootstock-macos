import Foundation

/// Describes a method by which an attacker could inject code into an app process.
public enum InjectionMethod: String, Codable, Sendable {
    /// No hardened runtime — DYLD_INSERT_LIBRARIES works unconditionally.
    case dyldInsert = "dyld_insert"
    /// Hardened runtime, but app has `allow-dyld-environment-variables` entitlement.
    case dyldInsertViaEntitlement = "dyld_insert_via_entitlement"
    /// Library validation is absent — unsigned dylibs can be loaded.
    case missingLibraryValidation = "missing_library_validation"
    /// Electron app — injectable via ELECTRON_RUN_AS_NODE environment variable.
    case electronEnvVar = "electron_env_var"
}
