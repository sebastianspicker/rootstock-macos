# Example Output: Multi-hop Injection Chain

**Query:** `06-injection-chain.cypher`
**Data source:** Typical macOS 14 developer workstation scan

## Results

```
╒══════════════════════════════════════════════╤══════════════════╤═════════════════════╤══════╕
│ chain                                        │ terminal_app     │ terminal_permission  │ hops │
╞══════════════════════════════════════════════╪══════════════════╪═════════════════════╪══════╡
│ ["Attacker Payload", "iTerm2", "Full Disk"]  │ "iTerm2"         │ "Full Disk Access"  │ 3    │
├──────────────────────────────────────────────┼──────────────────┼─────────────────────┼──────┤
│ ["Attacker Payload", "Slack", "Screen Rec."] │ "Slack"          │ "Screen Recording"  │ 3    │
└──────────────────────────────────────────────┴──────────────────┴─────────────────────┴──────┘
```

## Analysis

All paths are length 3 (2 hops) — a single injection step reaches the target permission.
No multi-hop chains were found (attacker → inject A → inject B → target), which suggests
the scanned system's injectable apps are not in each other's injection range.

A 3-hop chain (length 4) would look like:
`Attacker → inject VulnApp → VulnApp injects TargetApp → TargetApp has FDA`
