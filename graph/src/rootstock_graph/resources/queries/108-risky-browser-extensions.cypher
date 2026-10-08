// Name: Browser Extensions with Broad Access or Outside the Store
// Purpose: Extensions that can read and change every site (with their sensitive permissions), or that were loaded unpacked or side-loaded (external)
// Category: Blue Team
// Severity: High
// Parameters: none
// ATT&CK: T1176
// Prerequisites: rootstock-graph-import-scan must have run (collector module browserextensions)

MATCH (be:BrowserExtension)
WHERE be.broad_host_access = true
   OR be.install_location IN ['unpacked', 'external']
OPTIONAL MATCH (c:Computer {scan_id: be.scan_id})
RETURN c.hostname                    AS hostname,
       be.browser                    AS browser,
       be.profile                    AS profile,
       be.name                       AS extension_name,
       be.extension_id               AS extension_id,
       be.version                    AS version,
       be.install_location           AS install_location,
       be.from_webstore              AS from_webstore,
       be.enabled                    AS enabled,
       be.broad_host_access          AS broad_host_access,
       be.sensitive_permissions      AS sensitive_permissions,
       be.host_permissions[..5]      AS host_permissions,
       be.install_time               AS install_time,
       be.path                       AS path
ORDER BY CASE WHEN install_location IN ['unpacked', 'external'] THEN 0 ELSE 1 END,
         size(sensitive_permissions) DESC, browser ASC, extension_name ASC
