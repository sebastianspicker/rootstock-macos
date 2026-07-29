# Rootstock Blue security policy

Use the repository's [private vulnerability reporting
process](../SECURITY.md#reporting-a-vulnerability) for defects in Rootstock
Blue. Do not put exploit details, real case data, or copied forensic artifacts
in a public issue.

Reports are in scope when they concern:

- case-package integrity or custody validation;
- path traversal or unsafe archive handling;
- unintended secret or artifact exposure;
- Endpoint Security event loss, authorization, or blocking defaults;
- XPC capability expansion or privilege-boundary failures;
- malicious or untrusted detection content handling.

Requests to bypass System Integrity Protection, TCC, Full Disk Access,
FileVault, or Secure Enclave protections are outside the product scope.
