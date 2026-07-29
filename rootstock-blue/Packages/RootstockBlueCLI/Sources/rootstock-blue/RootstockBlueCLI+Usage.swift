import Foundation
import RootstockBlueCore

extension RootstockBlueCLI {
    static func printUsage() {
        print(usageText)
    }

    private static let usageText = """
        rootstock-blue - post-incident macOS DFIR + IR case platform (\(RootstockBlueVersion.string))

        Usage:
          rootstock-blue version
          rootstock-blue case create <path.rsbcase> [--name NAME]
          rootstock-blue case open <path.rsbcase>
          rootstock-blue case verify <path.rsbcase>
          rootstock-blue parse <artifact-tree> --case <path.rsbcase>
          rootstock-blue collect <pack> --case <path.rsbcase> --source <tree> [--content-root PATH] [--offline]
          rootstock-blue import scan-json <scan.json> --case <path.rsbcase>
          rootstock-blue import findings-jsonl <findings.jsonl> --case <path.rsbcase>
          rootstock-blue record inject --case <path.rsbcase> --jsonl <events.jsonl> [--profile ir|research|quiet]
          rootstock-blue timeline <path.rsbcase> [--limit N]
          rootstock-blue query <path.rsbcase> <SQL>
          rootstock-blue export jsonl <path.rsbcase> <out.jsonl>
          rootstock-blue export family <path.rsbcase> <out.json>
          rootstock-blue report markdown <path.rsbcase> <out.md>
          rootstock-blue detect run --ruleset samples [--content-root PATH] [--case <path.rsbcase>]
          rootstock-blue ir posture --case <path.rsbcase> [--source <artifact-tree>] [--live]
          rootstock-blue ir harden --case <path.rsbcase> [--source <artifact-tree>] [--live]
          rootstock-blue ir triage --case <path.rsbcase> --source <artifact-tree> [--content-root PATH] [--offline]
          rootstock-blue santa ingest <log.jsonl> --case <path.rsbcase>
          rootstock-blue preflight <pack> [--content-root PATH] [--offline]
          rootstock-blue uls status
          rootstock-blue uls parse <logarchive> --out <events.jsonl>

        Post-incident DFIR loop:
          case create → parse rooted evidence (and/or collect)
          → ir posture → ir harden → detect (fixtures or --case) → report markdown
          → timeline + query → export jsonl  (custody + hashes updated)
          Or one-shot: ir triage --case ... --source ... (parse+posture+harden+inventory+detect)

        Parsers include: TCC, Quarantine, Autostart, Users, Safari, Chromium,
        knowledgeC + Biome (PoL), RecentItems, Terminal, FSEvents, XProtect,
        BasicInfo, InstallHistory, Dock, BTM, WIFI, CONFIGPROFILES, SSH,
        CRON, LOGINITEMS, SYSTEMEXTENSIONS, UTMPX, BROWSER_EXTENSIONS,
        GATEKEEPER, NETLOCATION, SHELLPROFILES, EMOND, SUDOERS, LAUNCHDOVERRIDES,
        PRIVHELPERS, FOLDERACTIONS, LOGINHOOKS, AUTHPLUGINS, NETUSAGE, USBHISTORY,
        KEYCHAINMETA, CODESIGN, ARD, SPOTLIGHT, TRASH, DOCREVISIONS, SAVEDSTATE,
        FIREFOX, NOTIFICATIONS, QUICKLOOK, SCREENTIME, ICLOUD,
        COOKIES, BOOKMARKS, OFFICEMRU, PRINTJOBS, NOTES, IDEVICEBACKUP, MSRDC, CLOUDSYNC,
        PACKAGEKITDESIGN, ARCHIVEEXTRACTOR, INFOSTEALERPATH, TCCESFVISIBILITY.
        IR posture: FileVault/Firewall/SIP/Gatekeeper/XProtect/MRT/FDA +
        System Extensions / Screen Sharing / Remote Login / File Sharing /
        Guest+auto-login / Lockdown Mode / Software Update catalog (confidence + ir.mode).
        Hardening assessment: structured findings + remediation (not MDM/AV),
        including Wave-7 cookie/bookmark/office/print/notes/idevice/msrdc/cloudsync and
        Wave-8 packagekit/archive-extractor/stealer-path/tcc-esf-visibility controls.
        Persistence inventory: Autostart + BTM + Cron + LoginItems + ShellProfiles +
        Emond + PrivilegedHelpers + FolderActions + LoginHooks + AuthPlugins + SavedState + SSH keys.

        Collect packs: triage-lite, forensic-triage, post-incident-ir, browser,
        collab, persistence, logs, network-context, access-surface.

        Live ES mock inject works without FDA/entitlement; AUTH/block remains off.
        Santa: integrate-only decision log ingest (JSONL) → case timeline; no rule engine.
        ULS requires ROOTSTOCK_BLUE_ULS_BINARY (Mandiant macos-unifiedlogs); honest fail if unset.
        Non-goals: FileVault/SE crack, multi-OS EDR, SIEM, MDM, RAM forensics.
        """
}
