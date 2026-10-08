// Name: Recently Installed Packages
// Purpose: Installer package receipts written in the days before the scan, third-party packages first, with the apps they installed
// Category: Forensic
// Severity: Informational
// Parameters: $days (default: 30) - look-back window in days before the scan
// ATT&CK: T1072, T1195
// Prerequisites: rootstock-graph-import-scan must have run (collector module installedpackages)

MATCH (ip:InstalledPackage)-[:INSTALLED_ON]->(c:Computer)
WHERE ip.install_date IS NOT NULL
  AND datetime(ip.install_date) >= datetime(coalesce(c.scanned_at, toString(datetime()))) - duration({days: $days})
OPTIONAL MATCH (a:Application)-[:INSTALLED_BY]->(ip)
WITH c, ip, collect(DISTINCT a.name) AS applications
RETURN c.hostname            AS hostname,
       ip.package_id         AS package_id,
       ip.version            AS version,
       ip.install_date       AS install_date,
       ip.install_process    AS install_process,
       ip.package_file_name  AS package_file_name,
       ip.install_prefix     AS install_prefix,
       ip.is_apple           AS is_apple,
       applications
ORDER BY is_apple ASC, install_date DESC, package_id ASC
