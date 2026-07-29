# Red Lab boundary

`rootstock-red-lab` is a separate executable for reversible technique
validation on authorized lab hosts. It is not linked into the default
`rootstock-red` assessment executable.

Lab actions require authorization metadata and default to dry-run behavior.
Some actions can create or remove state after the operator explicitly selects a
non-dry-run path. These actions are intended to produce observable,
documented artifacts for purple-team validation, not stealth persistence.

The following packages are outside the supported default assessment runtime:

- `RootstockLab`
- `MacAgentKit`
- `MacTransportKit`
- `RootstockMythicAdapter`

The transport packages are unlinked skeletons. They are not a
supported C2, implant, or transport product.

Use Red Lab only under written rules of engagement. See
[Acceptable use](ACCEPTABLE_USE.md) and [Security policy](SECURITY.md).
