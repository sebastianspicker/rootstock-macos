# Velociraptor and UAC interchange

ZIP archive import is disabled in this alpha. Prepare an already-extracted
Velociraptor or UAC tree in a separate, isolated process, then parse that tree
into an existing case:

```bash
rootstock-blue parse <artifact-tree> --case <path.rsbcase>
```

Rootstock Blue does not run Velociraptor VQL, extract collection archives,
collect from remote hosts, or provide a multi-platform server.
