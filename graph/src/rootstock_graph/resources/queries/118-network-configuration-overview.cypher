// Name: DNS, Proxy and Hosts File Overview
// Purpose: Per host: DNS servers and search domains, enabled proxy / PAC settings, and /etc/hosts entries beyond the macOS defaults
// Category: Forensic
// Severity: Informational
// Parameters: none
// ATT&CK: T1090, T1565.001
// Prerequisites: rootstock-graph-import-scan must have run

MATCH (c:Computer)
RETURN c.hostname                         AS hostname,
       c.dns_servers                      AS dns_servers,
       c.search_domains                   AS search_domains,
       coalesce(c.proxy_count, 0)         AS proxy_count,
       c.proxy_settings                   AS proxy_settings,
       coalesce(c.hosts_entry_count, 0)   AS hosts_entry_count,
       c.hosts_entries                    AS hosts_entries,
       c.dns_servers IS NOT NULL          AS network_configuration_collected
ORDER BY proxy_count + hosts_entry_count DESC, hostname ASC
