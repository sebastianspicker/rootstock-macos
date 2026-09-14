# Synthetic event profiles

`record inject` uses a profile to choose which labels it will accept from a
synthetic JSONL fixture. Profiles are filters for controlled test input. They do
not connect to Endpoint Security, install a system extension, or authorize or
block activity.

| Profile | Fixture use | Labels (summary) |
| --- | --- | --- |
| `triage` | General triage fixtures | process, authentication, persistence, protection |
| `research` | Broader research fixtures | file, XPC, and process labels |
| `quiet` | Smaller fixture set | process, persistence, protection |

Swift callers select the same definitions with
`SyntheticEventProfile.builtin(_:)`.
