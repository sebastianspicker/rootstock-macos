# Product Specs — Index

> Feature specifications from the user's perspective.
> Each spec describes a use case and what "good" looks like.

## Target Users

1. **Red Team Operator** — Running an engagement, has initial access to a Mac, needs to
   find privilege escalation paths to sensitive resources (FDA, Keychain, credentials)
2. **Blue Team / macOS Admin** — Wants to audit the TCC grant landscape, find overly
   permissive apps, identify injectable applications before attackers do
3. **Security Researcher** — Studying macOS security mechanisms, needs structured data
   about real-world configurations to identify systemic weaknesses

## Specs

| ID | Title | Status | User |
|---|---|---|---|
| PS-001 | [Single-host scan and analysis](./ps-001-single-host-scan.md) | Active | All |
| PS-002 | Find injectable apps with TCC grants | Planned | Red Team |
| PS-003 | TCC grant audit report | Planned | Blue Team |
| PS-004 | Multi-host comparison | Future | Blue Team |
| PS-005 | Integration with BloodHound CE (OpenGraph) | Future | Red Team |
