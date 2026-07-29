import Models

public enum ApplicationTestFactory {
    public struct Options {
        let signing: Application.Signing
        let security: Application.Security
        let entitlementState: Application.EntitlementState
        let sandboxProfile: SandboxProfile?
        let quarantineInfo: QuarantineInfo?

        public init(
            signing: Application.Signing = Application.Signing(
                hardenedRuntime: true,
                libraryValidation: true,
                signed: true
            ),
            security: Application.Security = Application.Security(),
            entitlementState: Application.EntitlementState = Application.EntitlementState(),
            sandboxProfile: SandboxProfile? = nil,
            quarantineInfo: QuarantineInfo? = nil
        ) {
            self.signing = signing
            self.security = security
            self.entitlementState = entitlementState
            self.sandboxProfile = sandboxProfile
            self.quarantineInfo = quarantineInfo
        }
    }

    public static func make(
        name: String = "TestApp",
        bundleId: String = "com.example.test",
        path: String = "/Applications/TestApp.app",
        version: String? = "1.0",
        flags: Application.Flags = Application.Flags(isElectron: false, isSystem: false),
        options: Options = Options()
    ) -> Application {
        Application(
            identity: Application.Identity(
                name: name,
                bundleId: bundleId,
                path: path,
                version: version
            ),
            flags: flags,
            signing: options.signing,
            security: options.security,
            entitlementState: options.entitlementState,
            sandboxProfile: options.sandboxProfile,
            quarantineInfo: options.quarantineInfo
        )
    }
}
