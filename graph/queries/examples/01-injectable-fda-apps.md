# Example Output: Injectable Full Disk Access Apps

**Query:** `01-injectable-fda-apps.cypher`
**Data source:** Typical macOS 14 developer workstation scan

## Results

```
╒══════════════════════╤═══════════════════════════════════════╤═════════════════╤═════════════════════════════════════════════════════╤══════════════╕
│ app_name             │ bundle_id                             │ team_id         │ injection_methods                                   │ method_count │
╞══════════════════════╪═══════════════════════════════════════╪═════════════════╪═════════════════════════════════════════════════════╪══════════════╡
│ "iTerm2"             │ "com.googlecode.iterm2"               │ "H7V7XYVQ7D"   │ ["missing_library_validation", "dyld_insert"]       │ 2            │
├──────────────────────┼───────────────────────────────────────┼─────────────────┼─────────────────────────────────────────────────────┼──────────────┤
│ "Finder"             │ "com.apple.finder"                    │ null            │ ["missing_library_validation"]                      │ 1            │
└──────────────────────┴───────────────────────────────────────┴─────────────────┴─────────────────────────────────────────────────────┴──────────────┘
```

## Analysis

- **iTerm2** is injectable via 2 methods AND has Full Disk Access — critical finding.
  An attacker with code execution in iTerm2's process can read `/Library/Application Support/com.apple.TCC/TCC.db`
  and any other file on the system.
- **Finder** appears (null team_id = platform binary). In practice, SIP prevents injection
  into platform binaries — this is documented as a known false positive (TD-006).

## Remediation

- For iTerm2: enable Hardened Runtime in Xcode build settings and remove the
  `com.apple.security.cs.disable-library-validation` entitlement if present.
- Grant FDA only to apps that truly require it. Revoke iTerm2's FDA if iTerm2's
  file panel is used instead.
