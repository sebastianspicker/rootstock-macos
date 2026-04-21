import Models

/// Result of an injection assessment for a single app.
struct InjectionAssessmentResult {
    let methods: [InjectionMethod]
    let effectiveLibraryValidation: Bool
}

/// Determines which injection methods are applicable to an app,
/// based on its code signing state and entitlements.
struct InjectionAssessment {

    /// Entitlement keys checked during injection assessment.
    static let allowDyldEntitlement = "com.apple.security.cs.allow-dyld-environment-variables"
    static let disableLibraryValidationEntitlement = "com.apple.security.cs.disable-library-validation"

    /// Assess injection methods and effective library validation for the given app.
    ///
    /// SIP-protected apps cannot be injected — returns empty methods immediately.
    func assess(
        signingInfo: CodeSigningInfo,
        entitlements: [EntitlementInfo],
        isElectron: Bool,
        isSipProtected: Bool = false
    ) -> InjectionAssessmentResult {
        let names = Set(entitlements.map(\.name))

        // Library validation: CS_REQUIRE_LV flag OR
        // (hardened runtime AND no disable-library-validation entitlement).
        let hasDisableLV = names.contains(Self.disableLibraryValidationEntitlement)
        let effectiveLV = signingInfo.libraryValidationFlag
            || (signingInfo.hardenedRuntime && !hasDisableLV)

        // SIP-protected apps are immune to all injection methods.
        if isSipProtected {
            return InjectionAssessmentResult(methods: [], effectiveLibraryValidation: effectiveLV)
        }

        var methods: [InjectionMethod] = []

        // DYLD_INSERT_LIBRARIES injection
        if !signingInfo.hardenedRuntime {
            methods.append(.dyldInsert)
        } else if names.contains(Self.allowDyldEntitlement) {
            methods.append(.dyldInsertViaEntitlement)
        }

        if !effectiveLV {
            methods.append(.missingLibraryValidation)
        }

        // Electron — injectable via ELECTRON_RUN_AS_NODE
        if isElectron {
            methods.append(.electronEnvVar)
        }

        return InjectionAssessmentResult(
            methods: methods,
            effectiveLibraryValidation: effectiveLV
        )
    }
}
