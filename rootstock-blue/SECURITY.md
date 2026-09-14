# Rootstock Blue security policy

Report Rootstock Blue vulnerabilities through the repository's
[private reporting process](../SECURITY.md#reporting-a-vulnerability). Keep
exploit details, real case data, and copied forensic artifacts out of public
issues.

Reports are in scope when they concern:

- case-package integrity or custody validation;
- path traversal or unsafe archive handling;
- unintended secret or artifact exposure;
- synthetic event loss or unintended fixture-processing behavior;
- malicious or untrusted detection content handling.

Case checksums show whether the files inside a package agree with its inventory;
they do not authenticate the original evidence or its collector. Review custom
detection content and imported artifacts before use. A sidecar configured with
`ROOTSTOCK_BLUE_ULS_BINARY` runs with the Blue process identity, so select a
reviewed binary from a path that unprivileged users cannot modify.

Requests to bypass System Integrity Protection, TCC, Full Disk Access,
FileVault, or Secure Enclave protections are outside the product scope.
