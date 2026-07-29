# Contributing to Rootstock Blue

Read the root [contribution guide](../CONTRIBUTING.md) first.

Rootstock Blue changes must preserve these boundaries:

1. Offline fixture-backed analysis is the primary alpha test path.
2. Detection rules require matching synthetic fixtures.
3. Endpoint Security callbacks must keep bounded work and visible loss counts.
4. `RootstockBlueESKit` must not depend on `RootstockBlueFX`.
5. Privileged XPC operations must remain allowlisted.
6. External tools such as Santa and unified-log parsers remain optional
   integrations rather than copied implementations.
7. Secret extraction and security-control bypasses are outside project scope.

Run:

```bash
make bootstrap
make test
make content-validate
make check-non-goals
swift run rootstock-blue detect run --ruleset samples
```

Real case packages, copied artifacts, reports, and live event data must not be
included in issues, pull requests, or fixtures.

Rootstock Blue uses Apache-2.0 under [LICENSE](LICENSE). The sibling shared
package `packages/RootstockMacFacts` has an unresolved license scope and must
not be published independently.
