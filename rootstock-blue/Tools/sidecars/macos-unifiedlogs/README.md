# Mandiant macos-UnifiedLogs sidecar

Do not rewrite Unified Log parsing in Python.

1. Build or download [mandiant/macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs)  
2. Export path:

```bash
export ROOTSTOCK_BLUE_ULS_BINARY=/path/to/unifiedlog_iterator
```

3. When configured, `UnifiedLogsSidecar` invokes the binary as an out-of-process
   parser. The sidecar is not bundled with Rootstock Blue.
