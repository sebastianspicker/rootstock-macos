# Example Output: TCC Grant Overview (Blue Team)

**Query:** `07-tcc-grant-overview.cypher`
**Data source:** Typical macOS 14 developer workstation scan

## Section 1: Grants per permission type

```
╒════════════════════════╤══════════════════════════════════════╤═══════════════╤══════════════╤══════════════╕
│ permission             │ service                              │ allowed_count │ denied_count │ total_grants │
╞════════════════════════╪══════════════════════════════════════╪═══════════════╪══════════════╪══════════════╡
│ "Accessibility"        │ "kTCCServiceAccessibility"           │ 8             │ 2            │ 10           │
├────────────────────────┼──────────────────────────────────────┼───────────────┼──────────────┼──────────────┤
│ "Automation"           │ "kTCCServiceAppleEvents"             │ 15            │ 3            │ 18           │
├────────────────────────┼──────────────────────────────────────┼───────────────┼──────────────┼──────────────┤
│ "Screen Recording"     │ "kTCCServiceScreenCapture"           │ 4             │ 1            │ 5            │
├────────────────────────┼──────────────────────────────────────┼───────────────┼──────────────┼──────────────┤
│ "Full Disk Access"     │ "kTCCServiceSystemPolicyAllFiles"    │ 3             │ 0            │ 3            │
└────────────────────────┴──────────────────────────────────────┴───────────────┴──────────────┴──────────────┘
```

## Section 2: Most-permissioned apps

```
╒══════════════╤══════════════════════════════╤═══════════╤════════════════════════════════════════════════════╤══════════════════╕
│ app_name     │ bundle_id                    │ is_system │ permissions                                        │ permission_count │
╞══════════════╪══════════════════════════════╪═══════════╪════════════════════════════════════════════════════╪══════════════════╡
│ "Slack"      │ "com.tinyspeck.slackmacgap"  │ false     │ ["Microphone", "Camera", "Screen Recording"]       │ 3                │
├──────────────┼──────────────────────────────┼───────────┼────────────────────────────────────────────────────┼──────────────────┤
│ "iTerm2"     │ "com.googlecode.iterm2"       │ false     │ ["Accessibility", "Full Disk Access"]              │ 2                │
└──────────────┴──────────────────────────────┴───────────┴────────────────────────────────────────────────────┴──────────────────┘
```

## Section 3: Auth reason breakdown

```
╒═══════════════════╤═════╕
│ granted_by        │ n   │
╞═══════════════════╪═════╡
│ "user_settings"   │ 24  │
├───────────────────┼─────┤
│ "user_prompt"     │ 12  │
├───────────────────┼─────┤
│ "entitlement"     │ 8   │
├───────────────────┼─────┤
│ "mdm"             │ 0   │
└───────────────────┴─────┘
```

## Analysis

- 3 apps have Full Disk Access — audit each to confirm it's required.
- 0 MDM-managed grants — consistent with a personal/developer machine (not enterprise-managed).
- 8 entitlement-based grants — apps with private entitlements bypass user consent entirely.
- Automation (18 grants) is the most widely-granted permission — largest Apple Event attack surface.
