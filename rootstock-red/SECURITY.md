# Rootstock Red security policy

Report Rootstock Red vulnerabilities through the repository's
[private reporting process](../SECURITY.md#reporting-a-vulnerability). Relevant
reports include unsafe defaults, path traversal, privilege-boundary errors,
authorization bypasses, unexpected network access, and secret exposure.

Do not publish exploit details in an issue before maintainers have assessed the
report.

The project does not accept feature requests for weaponized unpatched exploits,
credential theft, or packaged detection bypasses. See the
[acceptable-use policy](ACCEPTABLE_USE.md) for the intended scope.

The expected safety controls are:

- `rootstock-red` currently has no network client. `--allow-network` records an
  explicit opt-in for a future or registered network-aware module. Report any
  network path that ignores this setting.
- `rootstock-red-lab` is a separate executable. It requires operator and scope
  metadata and starts in dry-run mode. These values are records, not proof of
  authorization.
- The local kill switch is `~/.rootstock-red/DISABLE`. It is a same-user safety
  control, not an administrator-enforced policy.

Some lab actions accept operator-selected paths. Review the dry-run plan and
resolved target paths before passing `--no-dry-run`. Report any action that
writes outside its documented scope or cannot clean up the state it creates.

Report any path that bypasses these controls as a security issue.
