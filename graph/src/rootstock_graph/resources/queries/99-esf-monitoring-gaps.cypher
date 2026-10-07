// Name: ESF Monitoring Gaps
// Purpose: Report critical ESF event types with no active SystemExtension monitoring them; when no endpoint-security extension was recorded, return a single row saying so
// Category: Blue Team
// Severity: High
// Prerequisites: rootstock-graph-import-scan + rootstock-graph-infer must have run
OPTIONAL MATCH (se:SystemExtension {extension_type: 'endpoint_security', enabled: true})
WHERE se.subscribed_events IS NOT NULL
WITH collect(se) AS esf_extensions
WITH esf_extensions,
     reduce(all_events = [], se IN esf_extensions |
       all_events + coalesce(se.subscribed_events, [])) AS monitored_events,
     ['AUTH_EXEC', 'AUTH_OPEN', 'AUTH_KEXTLOAD', 'AUTH_MOUNT', 'AUTH_SIGNAL',
      'NOTIFY_EXEC', 'NOTIFY_FORK', 'NOTIFY_EXIT', 'NOTIFY_CREATE', 'NOTIFY_WRITE',
      'NOTIFY_RENAME', 'NOTIFY_LINK', 'NOTIFY_UNLINK', 'NOTIFY_MMAP',
      'NOTIFY_KEXTLOAD', 'NOTIFY_MOUNT', 'NOTIFY_UNMOUNT'] AS critical_events
UNWIND (CASE WHEN size(esf_extensions) = 0 THEN [null] ELSE critical_events END) AS event
WITH event, monitored_events, esf_extensions
WHERE event IS NULL OR NOT event IN monitored_events
RETURN CASE WHEN event IS NULL THEN 'ALL' ELSE event END AS critical_event,
       false AS is_monitored,
       CASE WHEN event IS NULL
            THEN 'NO ENDPOINT-SECURITY EXTENSION RECORDED'
            ELSE 'NO ACTIVE MONITOR' END AS status
ORDER BY critical_event;
