// Name: ESF Monitoring Gaps
// Purpose: Detect critical ESF event types that have no active SystemExtension monitoring them
// Category: Blue Team
// Severity: High
// Prerequisites: import.py + infer.py must have run
MATCH (se:SystemExtension {extension_type: 'endpoint_security', enabled: true})
WHERE se.subscribed_events IS NOT NULL
WITH collect(se) AS esf_extensions,
     reduce(all_events = [], se IN collect(se) |
       all_events + coalesce(se.subscribed_events, [])) AS monitored_events
WITH esf_extensions,
     ['AUTH_EXEC', 'AUTH_OPEN', 'AUTH_KEXTLOAD', 'AUTH_MOUNT', 'AUTH_SIGNAL',
      'NOTIFY_EXEC', 'NOTIFY_FORK', 'NOTIFY_EXIT', 'NOTIFY_CREATE', 'NOTIFY_WRITE',
      'NOTIFY_RENAME', 'NOTIFY_LINK', 'NOTIFY_UNLINK', 'NOTIFY_MMAP',
      'NOTIFY_KEXTLOAD', 'NOTIFY_MOUNT', 'NOTIFY_UNMOUNT'] AS critical_events,
     monitored_events
UNWIND critical_events AS event
WITH event,
     CASE WHEN event IN monitored_events THEN true ELSE false END AS is_monitored,
     [se IN esf_extensions WHERE event IN coalesce(se.subscribed_events, []) | se.identifier] AS monitors
WHERE NOT event IN monitored_events
RETURN event AS critical_event,
       is_monitored,
       'NO ACTIVE MONITOR' AS status
ORDER BY event;
