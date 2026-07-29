# Technique catalog

Stable family technique IDs map the same macOS security narratives across:

- graph Cypher queries (`graph/queries/`)
- rootstock-red finding/vector IDs (`rootstock.vector.*`, `rootstock.check.*`)
- rootstock-blue detection samples (`rootstock-blue/Content/detections/samples/`)

## Source of truth

[`technique-catalog.yaml`](technique-catalog.yaml) is authoritative. This page
is a human index. Validate references:

```bash
python3 scripts/check-technique-catalog.py
```

## Index (excerpt)

The YAML catalog contains 79 techniques. This page groups them by stable
security domain.

### Seed techniques

| Family ID | Title | Status |
|-----------|-------|--------|
| `rootstock.tech.fda_pivot` | Full Disk Access permission pivot | mapped |
| `rootstock.tech.tcc_inheritance` | Child / third-party TCC inheritance | mapped |
| `rootstock.tech.injection_surface` | Injection without HR / LV | mapped |
| `rootstock.tech.mdm_overgrant` | MDM / PPPC overgrant | mapped |
| `rootstock.tech.sudoers_nopasswd` | Sudoers NOPASSWD | mapped |
| `rootstock.tech.auth_plugins` | Non-Apple authorization plugins | mapped |
| `rootstock.tech.unsigned_persistence` | Unsigned / weak persistence | mapped |
| `rootstock.tech.btm_loginitems` | BTM / login items honesty | mapped |
| `rootstock.tech.user_launchagents` | User LaunchAgents | mapped |
| `rootstock.tech.shell_hooks` | Shell profile / DYLD hooks | mapped |
| `rootstock.tech.keychain_metadata` | Keychain metadata surface | mapped |
| `rootstock.tech.system_extensions` | System extensions inventory | mapped |
| `rootstock.tech.kerberos_artifacts` | Kerberos / ccache exposure | mapped |
| `rootstock.tech.quarantine_gatekeeper` | Quarantine / Gatekeeper gaps | mapped |
| `rootstock.tech.esf_sensor_gap` | ESF / EDR sensor gap | mapped |
| `rootstock.tech.packagekit_installer_design` | PackageKit installer design posture | mapped |
| `rootstock.tech.archive_quarantine_extractor` | Archive / quarantine extractor surface | mapped |
| `rootstock.tech.infostealer_path_plane` | Info-stealer multi-app path plane | mapped |
| `rootstock.tech.tcc_esf_visibility_depth` | TCC / ESF visibility-depth posture | mapped |

See YAML for per-product mappings, depth notes, and ATT&CK tags.

## Installer, quarantine, collection, and visibility

Four technique themes map Red path-to-impact checks and lab plans to Blue
hardening controls and detection samples. Catalog status is `mapped` for each
pair.

## Delivery, persistence, and automation

| Technique ID | Title | Status |
|--------------|-------|--------|
| `rootstock.tech.url_scheme_handler` | Custom URL scheme / document-handler delivery | mapped |
| `rootstock.tech.launchd_override_depth` | Launchd disabled / override depth (security-product disable) | mapped |
| `rootstock.tech.browser_extension_dualuse` | Browser extension dual-use persistence / collection | mapped |
| `rootstock.tech.shortcuts_app_intents` | Shortcuts / App Intents automation lateral | mapped |

Each theme maps a Red collector, vector, compound check, and dry-run lab plan
to a Blue parser, hardening control, and detection fixture.

## Automation, logging, and network shares

| Technique ID | Title | Status |
|--------------|-------|--------|
| `rootstock.tech.webloc_inetloc_delivery` | Webloc / Internet Location file delivery | mapped |
| `rootstock.tech.mail_rules_automation` | Mail rules / Apple Mail automation persistence | mapped |
| `rootstock.tech.unified_log_observation` | Unified log / logarchive observation depth | mapped |
| `rootstock.tech.dock_persistence_surface` | Dock persistent apps / recent items dual-use | mapped |
| `rootstock.tech.osascript_scpt_delivery` | Compiled AppleScript / OSA delivery residual | mapped |
| `rootstock.tech.network_share_mount` | Network share / SMB mount dual-use lateral | mapped |

Each theme maps a Red collector, vector, compound check, and dry-run lab plan
to a Blue parser, hardening control, and detection fixture.

## System policy and local services

| Technique ID | Title | Status |
|--------------|-------|--------|
| `rootstock.tech.calendar_reminders_automation` | Calendar / Reminders automation lateral surface | mapped |
| `rootstock.tech.gatekeeper_assessment_history` | Gatekeeper assessment / syspolicyd history depth | mapped |
| `rootstock.tech.homebrew_package_dualuse` | Homebrew / third-party package manager dual-use | mapped |
| `rootstock.tech.cups_print_dualuse` | CUPS / printer dual-use residual surface | mapped |
| `rootstock.tech.screencapture_privacy_dualuse` | ScreenCapture / screenshot privacy dual-use depth | mapped |

Each entry maps the implemented Red assessment path to the corresponding Blue
parser, hardening control, and detection sample.

## Local automation and metadata stores

| Technique ID | Title | Status |
|--------------|-------|--------|
| `rootstock.tech.automator_workflow` | Automator workflow delivery residual | mapped |
| `rootstock.tech.icloud_drive_path` | iCloud Drive / Mobile Documents path plane | mapped |
| `rootstock.tech.bluetooth_continuity_depth` | Bluetooth / Continuity proximity residual depth | mapped |
| `rootstock.tech.font_validation_dualuse` | Font validation / ATS dual-use surface | mapped |
| `rootstock.tech.quicklook_cache_depth` | QuickLook thumbnail cache residual depth | mapped |
| `rootstock.tech.dns_resolver_dualuse` | DNS resolver / mDNSResponder dual-use surface | mapped |
| `rootstock.tech.ls_quarantine_db_depth` | LaunchServices QuarantineEvents DB residual depth | mapped |
| `rootstock.tech.pam_auth_module` | PAM authentication module residual surface | mapped |
| `rootstock.tech.cron_at_job_depth` | Cron / at job dual-use residual depth | mapped |
| `rootstock.tech.notes_metadata_plane` | Notes.app metadata collection path plane | mapped |

Each entry maps the implemented Red assessment path to the corresponding Blue
parser, hardening control, and detection sample.

## Local data, services, and runtime surfaces

| Technique ID | Title | Status |
|--------------|-------|--------|
| `rootstock.tech.photos_library_path` | Photos.app library collection path plane | mapped |
| `rootstock.tech.vpn_config_dualuse` | VPN configuration dual-use residual surface | mapped |
| `rootstock.tech.sandbox_container_depth` | App sandbox container residual depth | mapped |
| `rootstock.tech.xpc_mach_service_depth` | XPC Mach service residual depth | mapped |
| `rootstock.tech.tm_local_snapshot_depth` | Time Machine local snapshot residual depth | mapped |
| `rootstock.tech.emond_legacy_depth` | Emond legacy rules residual depth | mapped |
| `rootstock.tech.screen_sharing_ard_depth` | Screen Sharing / ARD residual depth | mapped |
| `rootstock.tech.keychain_acl_path` | Keychain ACL path residual surface | mapped |
| `rootstock.tech.python_runtime_dualuse` | Python runtime dual-use residual surface | mapped |
| `rootstock.tech.shell_plugin_manager` | Shell plugin manager dual-use residual | mapped |

Each entry maps the implemented Red assessment path to the corresponding Blue
parser, hardening control, and detection sample.

## Application data and continuity surfaces

| Technique ID | Title | Status |
|--------------|-------|--------|
| `rootstock.tech.airplay_receiver_surface` | AirPlay receiver dual-use residual | mapped |
| `rootstock.tech.handoff_clipboard_depth` | Handoff / Universal Clipboard residual depth | mapped |
| `rootstock.tech.imessage_path_plane` | iMessage / Messages path collection plane | mapped |
| `rootstock.tech.facetime_camera_surface` | FaceTime / camera pipeline dual-use surface | mapped |
| `rootstock.tech.finder_sync_extension` | Finder Sync extension dual-use surface | mapped |
| `rootstock.tech.fileprovider_domain` | File Provider domain residual surface | mapped |
| `rootstock.tech.notification_center_depth` | Notification Center residual depth | mapped |
| `rootstock.tech.siri_suggestions_plane` | Siri / Suggestions data-access residual | mapped |
| `rootstock.tech.spotlight_importer_depth` | Spotlight importer residual depth | mapped |
| `rootstock.tech.contacts_path_plane` | Contacts database path residual plane | mapped |
| `rootstock.tech.calendar_server_path` | Calendar server / CalDAV residual surface | mapped |
| `rootstock.tech.reminders_cloud_path` | Reminders cloud path residual plane | mapped |
| `rootstock.tech.maps_location_path` | Maps / location services residual plane | mapped |
| `rootstock.tech.weather_widget_path` | Weather / widget data residual plane | mapped |
| `rootstock.tech.music_library_path` | Music / media library path residual | mapped |
| `rootstock.tech.books_path_plane` | Books / EPUB path residual plane | mapped |
| `rootstock.tech.podcasts_path_plane` | Podcasts library path residual | mapped |
| `rootstock.tech.tv_app_path_plane` | TV.app residual path plane | mapped |
| `rootstock.tech.homekit_path_plane` | HomeKit residual path plane | mapped |
| `rootstock.tech.health_path_plane` | Health app residual path plane | mapped |
| `rootstock.tech.wallet_pass_path` | Wallet / pass residual path plane | mapped |
| `rootstock.tech.findmy_path_plane` | Find My residual path plane | mapped |
| `rootstock.tech.shortcuts_icloud_sync` | Shortcuts iCloud sync residual depth | mapped |
| `rootstock.tech.devicemanagement_profile` | Device management profile residual depth | mapped |
| `rootstock.tech.softwareupdate_catalog` | Software Update catalog residual surface | mapped |

These entries cover application data stores, continuity features, extension
points, and device-management metadata.

## Adding a technique

1. Add an entry to `technique-catalog.yaml` with a stable `rootstock.tech.*` id.
2. Point `mappings` at real files/IDs or mark `status: planned`.
3. Run `python3 scripts/check-technique-catalog.py`.
4. When a graph inference or query lands, add Red and Blue mappings where the
   same surface applies without merging engines.
