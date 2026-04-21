# Cross-Cutting Issues — Full-Repo Review

> Discovered during Phases A–F review. To be resolved by `review-final-consistency.md`.

## P1 — High

1. **Owned-node traversal queries incomplete** (Queries 41, 42, 44, 45, 47, 57)
   Missing `CAN_CHANGE_PASSWORD`, `CAN_READ_KERBEROS`, `SHARES_KEYCHAIN_GROUP` from relationship type lists used for reachability analysis. These are attack-relevant edges that extend blast radius.

## P2 — Medium

2. **`firewall_status` missing from fixture_minimal.json**
   `FirewallPolicy` node import (`import_firewall_status`) has zero integration test coverage. The code path defaults to empty list and early-returns, so not broken, but untested.

3. **Query 62 unbounded variable-length path**
   `[:ISSUED_BY*0..]` in `62-non-apple-ca-chain.cypher` — certificate chains are shallow in practice but should be bounded (e.g., `*0..10`).

4. **Inference/import error handling**
   Both `infer.py` and `import.py` lack per-function try/except. A failure in one module aborts all subsequent modules.

5. **DOT label injection** in `report_graphviz.py`
   Node display names inserted into DOT `label="..."` without escaping double quotes. Low practical risk.

## P3 — Low

6. **`FDA_SERVICE` and `APPLE_EVENTS_SERVICE` constants unused**
   Defined in `constants.py` but hardcoded as string literals in queries and inference modules.

7. **9/13 inference modules lack dedicated test coverage**
   Modules without tests: `infer_esf`, `infer_file_acl`, `infer_finder_fda`, `infer_group_capabilities`, `infer_kerberos`, `infer_keychain_groups`, `infer_mdm_overgrant`, `infer_password`, `infer_shell_hooks`.

8. **`gatekeeper_enabled` absent from fixture_minimal.json**
   Optional boolean, defaults to `None`. Minor gap.
