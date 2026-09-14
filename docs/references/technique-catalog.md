# Technique catalog

Technique IDs link related macOS security topics across the products:

- packaged graph Cypher queries (`graph/src/rootstock_graph/resources/queries/`)
- rootstock-red finding/vector IDs (`rootstock.vector.*`, `rootstock.check.*`)
- rootstock-blue detection samples (`rootstock-blue/Content/detections/samples/`)

## Look up a technique

[`technique-catalog.yaml`](technique-catalog.yaml) contains the IDs and
mappings. To check that its references resolve, run this from the repository
root:

```bash
python3 scripts/check-technique-catalog.py
```

## Find a topic

Use the catalog's `surfaces` field to find techniques in these broad domains:

- privilege, privacy, and code execution: TCC, Full Disk Access, MDM, signing,
  injection, authorization, and sandbox boundaries;
- delivery, persistence, and automation: launchd, login items, shell hooks,
  document handlers, scripts, browser extensions, and scheduled jobs;
- collection, observability, and local services: keychain, logs, archives,
  network shares, system extensions, service configuration, and sensors;
- application and user-data surfaces: Apple application stores, continuity,
  extensions, device management, and cloud-connected metadata.

For a technique's stable ID, title, ATT&CK tags, depth notes, status, and
product mappings, search [`technique-catalog.yaml`](technique-catalog.yaml).
The mappings identify packaged graph queries, Red finding or check IDs, and
Blue detection samples without implying equivalent evidence depth.

## Adding a technique

1. Add an entry to `technique-catalog.yaml` with a stable `rootstock.tech.*` id.
2. Point `mappings` at real files or IDs, or mark `status: planned`.
3. Run `python3 scripts/check-technique-catalog.py`.
4. Add mappings where the same topic applies to another product. Keep each
   product's implementation separate.
