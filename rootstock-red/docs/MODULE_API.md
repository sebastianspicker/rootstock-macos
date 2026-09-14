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

Collectors gather host evidence and return a partial `CollectedState`. Use
Foundation or a specific system API instead of launching an arbitrary shell.
The runner records privilege failures and other collector errors in the merged
state, then continues the assessment. A collector defaults to the `.readOnly`
risk class.

## Check

```swift
public protocol Check: Sendable {
  static var id: String { get }
  static var riskClass: RiskClass { get }
  static var cost: CollectorCost { get }
  func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding]
}
```

Checks evaluate the merged state without changing the host. Finding identifiers
use `rootstock.check.<plane>.<name>`. Technique-oriented assessments use
`rootstock.vector.<family>.<name>` and the same `Check` protocol; they model a
risk path rather than delivering an exploit.

## Lab action

```swift
public protocol Action: Sendable {
  static var id: String { get }
  static var consent: ConsentPolicy { get }
  static var riskClass: RiskClass { get }
  func run(context: EvaluationContext) async throws -> ActionResult
}
```

The default assessment CLI never registers actions. The separate
`rootstock-red-lab` executable requires operator and scope metadata and starts
in dry-run mode. These inputs record the invocation but do not establish
external authorization. An action that supports `--no-dry-run` must report its
resolved writes and cleanup path.

`ModuleRegistry` owns collectors and checks. `ActionRegistry` exists only in
`RootstockLab`.
