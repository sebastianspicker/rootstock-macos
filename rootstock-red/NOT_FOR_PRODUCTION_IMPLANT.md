# Red Lab boundary

`rootstock-red-lab` is a separate executable for reversible technique
validation on authorized lab hosts. It is not linked into the default
`rootstock-red` assessment executable.

Lab actions require the operator to provide their identity and engagement
scope. They start in dry-run mode. This information records who invoked the
tool; it neither authenticates the operator nor proves authorization.

When an operator explicitly disables dry-run mode, some actions can create or
remove state at a selected path. Before running one, review its plan, resolved
paths, and cleanup instructions. The actions create observable artifacts for
purple-team validation and are not designed for stealth or persistence on a
production host.

The lab implementation lives in a package that the default assessment
executable does not link:

- `RootstockLab`

Use Red Lab only under written rules of engagement. See
[Acceptable use](ACCEPTABLE_USE.md) and [Security policy](SECURITY.md).
