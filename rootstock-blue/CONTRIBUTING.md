# Contributing to Rootstock Blue

Read the root [contribution guide](../CONTRIBUTING.md) first.

Keep the following product boundaries in mind when proposing a change:

1. Offline analysis with synthetic fixtures is the main alpha workflow.
2. Every detection rule needs a matching synthetic fixture.
3. `record inject` accepts fixture events. It is not a live Endpoint Security
   client.
4. Synthetic event processing must bound its workload and report dropped input.
5. `RootstockBlueSyntheticEvents` must remain independent of
   `RootstockBlueFX`.
6. Santa and unified-log tools remain optional integrations. Do not copy their
   implementations into Blue.
7. Do not add secret extraction or ways to bypass macOS security controls.

Before opening a pull request, run these commands from `rootstock-blue/`:

```bash
make bootstrap
make test
make content-validate
make check-non-goals
swift run rootstock-blue detect run --ruleset samples
```

Use synthetic data in tests and examples. Never attach a real case package,
copied artifact, report, or event stream to an issue or pull request.

Rootstock Blue uses Apache-2.0 under [LICENSE](LICENSE). The sibling
`RootstockMacFacts` package is separately licensed under Apache-2.0 and has no
independent runtime version.
