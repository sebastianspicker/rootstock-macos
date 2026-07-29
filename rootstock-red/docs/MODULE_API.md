# Module API

## Collector

```swift
public protocol Collector: Sendable {
  static var id: String { get }
  static var cost: CollectorCost { get }
  static var requires: [PrivilegeRequirement] { get }
  static var riskClass: RiskClass { get }
  func collect(context: EvaluationContext) async throws -> CollectedState
}
```

Collectors must not run an arbitrary shell. Prefer Foundation and system APIs.
Privilege denial is recorded in collected state rather than aborting the whole
assessment. The default risk class is `.readOnly`.

## Check

```swift
public protocol Check: Sendable {
  static var id: String { get }
  static var riskClass: RiskClass { get }
  static var cost: CollectorCost { get }
  func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding]
}
```

Regular finding identifiers use `rootstock.check.<plane>.<name>`. Technique
assessment identifiers use `rootstock.vector.<family>.<name>`. Vector checks
use the same protocol and do not deliver exploits.

## Lab action

```swift
public protocol Action: Sendable {
  static var id: String { get }
  static var consent: ConsentPolicy { get }
  static var riskClass: RiskClass { get }
  func run(context: EvaluationContext) async throws -> ActionResult
}
```

Actions are never registered in the default assessment CLI. The separate
`rootstock-red-lab` executable applies authorization checks and a dry-run
default. Any non-dry-run action must document its writes and removal path.

`ModuleRegistry` owns collectors and checks. `ActionRegistry` exists only in
`RootstockLab`.
