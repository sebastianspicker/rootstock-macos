# Example Output: Shortest Path to Full Disk Access

**Query:** `02-shortest-path-to-fda.cypher`
**Data source:** Typical macOS 14 developer workstation scan

## Results

```
path_length: 3
node_names:  ["Attacker Payload", "iTerm2", "Full Disk Access"]
rel_types:   ["CAN_INJECT_INTO", "HAS_TCC_GRANT"]
```

## Visual Graph (Neo4j Browser)

```
(attacker.payload)
    │
    │  CAN_INJECT_INTO {method: "missing_library_validation"}
    ▼
(iTerm2: Application)
    │
    │  HAS_TCC_GRANT {allowed: true}
    ▼
(Full Disk Access: TCC_Permission)
```

## Analysis

**Path length 3** (2 hops, via 1 intermediate app) — the minimum possible attack chain.

This path means:
1. Attacker places a malicious dylib that gets loaded into iTerm2 (e.g., via `DYLD_INSERT_LIBRARIES`
   or by writing to a path iTerm2 loads at startup).
2. Injected code runs with iTerm2's process permissions.
3. iTerm2 has FDA → injected code can read TCC.db, SSH keys, all user files.

**Severity: Critical.** A 2-hop path to FDA with well-documented injection techniques.

## If No Results

Zero results from this query means no injectable app on the system holds FDA.
This is a positive security finding. Document as: "No injectable FDA path found."
