/// Consent / ROE requirements for lab or destructive actions.
public struct ConsentPolicy: Codable, Sendable, Equatable {
    public var requiresAuthorizedFlag: Bool
    public var requiresScope: Bool
    public var requiresOperator: Bool
    public var requiresConfirmToken: String?

    public init(
        requiresAuthorizedFlag: Bool = true,
        requiresScope: Bool = true,
        requiresOperator: Bool = true,
        requiresConfirmToken: String? = nil
    ) {
        self.requiresAuthorizedFlag = requiresAuthorizedFlag
        self.requiresScope = requiresScope
        self.requiresOperator = requiresOperator
        self.requiresConfirmToken = requiresConfirmToken
    }

    public static let labDefault = ConsentPolicy()
}

/// Operator-supplied consent for a run.
public struct ConsentTokens: Codable, Sendable, Equatable {
    public var iAmAuthorized: Bool
    public var scope: String?
    public var operatorName: String?
    public var confirm: String?

    public init(
        iAmAuthorized: Bool = false,
        scope: String? = nil,
        operatorName: String? = nil,
        confirm: String? = nil
    ) {
        self.iAmAuthorized = iAmAuthorized
        self.scope = scope
        self.operatorName = operatorName
        self.confirm = confirm
    }

    public func satisfies(_ policy: ConsentPolicy) -> Bool {
        let authorizationSatisfied = !policy.requiresAuthorizedFlag || iAmAuthorized
        let scopeSatisfied = !policy.requiresScope || !(scope?.isEmpty ?? true)
        let operatorSatisfied = !policy.requiresOperator || !(operatorName?.isEmpty ?? true)
        let confirmationSatisfied = policy.requiresConfirmToken.map { confirm == $0 } ?? true
        return [authorizationSatisfied, scopeSatisfied, operatorSatisfied, confirmationSatisfied]
            .allSatisfy { $0 }
    }
}
