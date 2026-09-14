# Mandiant macos-UnifiedLogs sidecar

Rootstock Blue can call Mandiant's external `unifiedlog_iterator` rather than
embedding another Unified Log parser.

1. Build [mandiant/macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs)
   from a reviewed revision, or verify the provenance and checksum of a
   downloaded binary.
2. Set the absolute path to the executable:

```bash
export ROOTSTOCK_BLUE_ULS_BINARY=/path/to/unifiedlog_iterator
```

3. Parse a copied `.logarchive` into a new JSONL file:

```bash
rootstock-blue uls parse /path/to/system.logarchive --out /tmp/unifiedlogs.jsonl
```

`UnifiedLogsSidecar` launches the binary as a child process with Rootstock
Blue's identity and access. Store it in a directory that unprivileged users
cannot modify, and do not point the environment variable at an unreviewed
script or wrapper. Rootstock Blue does not bundle the sidecar.
