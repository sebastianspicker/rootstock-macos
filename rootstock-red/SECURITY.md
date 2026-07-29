# Rootstock Red security policy

Use the repository's [private vulnerability reporting
process](../SECURITY.md#reporting-a-vulnerability) for unsafe defaults, path
traversal, privilege-boundary errors, authorization bypasses, unintended
network access, secret exposure, or other defects in Rootstock Red.

Do not publish exploit details in an issue before maintainers have assessed the
report.

Requests for weaponized unpatched exploits, credential theft, or detection
bypass packaging are not feature requests for this project.

The expected safety controls are:

- `rootstock-red` performs assessment and has network egress disabled unless
  `--allow-network` is explicit.
- `rootstock-red-lab` is separate, requires authorization metadata, and uses a
  dry-run default.
- The local kill switch is `~/.rootstock-red/DISABLE`.

Report any path that bypasses these controls as a security issue.
