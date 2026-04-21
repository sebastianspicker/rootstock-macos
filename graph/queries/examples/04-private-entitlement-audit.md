# Example Output: Private Entitlement Audit

**Query:** `04-private-entitlement-audit.cypher`
**Data source:** Typical macOS 14 developer workstation scan

## Results

```
╒═══════════════════════╤═══════════════════════════════╤════════════╤═══════════════════════════════════════════════════════════════════╤═══════════════╤════════════════════════════════════════════════════╤═══════════════════╕
│ app_name              │ bundle_id                     │ signed     │ team_id        │ private_entitlements                                              │ is_injectable │ private_ent_count │
╞═══════════════════════╪═══════════════════════════════╪════════════╪════════════════╪═══════════════════════════════════════════════════════════════════╪═══════════════╪═══════════════════╡
│ "iTerm2"              │ "com.googlecode.iterm2"       │ true       │ "H7V7XYVQ7D"  │ ["com.apple.private.tcc.allow"]                                   │ true          │ 1                 │
├───────────────────────┼───────────────────────────────┼────────────┼────────────────┼───────────────────────────────────────────────────────────────────┼───────────────┼───────────────────┤
│ "Xcode"               │ "com.apple.dt.Xcode"          │ true       │ "59GAB85EFG"  │ ["com.apple.private.tcc.allow", "com.apple.security.get-task-allow"] │ false       │ 2                 │
└───────────────────────┴───────────────────────────────┴────────────┴────────────────┴───────────────────────────────────────────────────────────────────┴───────────────┴───────────────────┘
```

## Analysis

- **iTerm2** has `com.apple.private.tcc.allow` (silent TCC bypass) AND is injectable — critical.
- **Xcode** has `get-task-allow` (debugger attachment) which is expected for development tools.
  Xcode is not injectable (hardened runtime), reducing risk.

## Note

`com.apple.private.tcc.allow` is the most dangerous private entitlement:
it grants TCC access without user consent prompts. Combined with injectability,
an attacker can silently inherit all TCC services the app is entitled to.
