"""Family, campaign, engagement, fleet, and timeline report renderers."""

from __future__ import annotations

from family_finding_classification import is_red_family_finding
from report_diagram_common import safe_label
from utils import sanitize_id as sanitize_mermaid_id


def mermaid_family_findings_block(findings: list[dict], *, source: str | None = None, max_findings: int = 8) -> str:
    """Render a Mermaid flowchart of family open-export findings."""
    if not findings:
        return "_No family findings to diagram._"
    lines = ["```mermaid", "flowchart TB"]
    lines.append('  subgraph FamilyFindings["Family findings (red / blue)"]')
    red_ids: list[str] = []
    blue_ids: list[str] = []
    for index, finding in enumerate(findings[:max_findings]):
        node_id, label, is_red = _family_finding_node(finding, index, source)
        lines.append(f'    {node_id}["{label}"]')
        (red_ids if is_red else blue_ids).append(node_id)
    lines.append("  end")
    for node_id in red_ids:
        lines.append(f"  style {node_id} fill:#c0392b,color:#fff,stroke:#7b241c")
    for node_id in blue_ids:
        lines.append(f"  style {node_id} fill:#2471a3,color:#fff,stroke:#1a5276")
    lines.append("```")
    return "\n".join(lines)


def _family_finding_node(finding: dict, index: int, source: str | None) -> tuple[str, str, bool]:
    finding_id = _family_finding_id(finding, index)
    title = str(finding.get("name") or finding.get("title") or finding_id)
    severity = str(finding.get("severity") or "info").lower()
    is_red = is_red_family_finding(finding, finding_id, source)
    node_id = sanitize_mermaid_id(f"f{index}_{finding_id}")[:48]
    label = safe_label(f"{'[R] ' if is_red else '[B] '}{title} ({severity})", max_len=42)
    return node_id, label, is_red


def _family_finding_id(finding: dict, index: int = 0) -> str:
    return str(finding.get("finding_id") or finding.get("id") or finding.get("name") or f"finding_{index}")


def _family_finding_row(finding: dict, source: str | None = None) -> str:
    finding_id = _family_finding_id(finding)
    title = str(finding.get("name") or finding.get("title") or finding_id).replace("|", "/")
    severity = str(finding.get("severity") or "info")
    side = "red" if is_red_family_finding(finding, finding_id, source) else "blue"
    return f"| {side} | `{finding_id}` | {severity} | {title} |"


def format_family_findings_section(findings: list[dict], *, source: str | None = None, max_findings: int = 12) -> str:
    """Markdown section: family findings table + Mermaid diagram."""
    if not findings:
        return "## Family Red/Blue Findings\n\n_No family open-export findings provided._\n"
    parts = [
        "## Family Red/Blue Findings", "",
        "> **Purple narrative:** Red findings are path-to-impact / assess surfaces; blue findings are offline harden/detect/forensic controls. Distinct OpenGraph kinds (`rs_RedFinding` / `rs_BlueFinding`) keep them legible in the viewer.", "",
        "| Side | Finding ID | Severity | Title |", "|------|------------|----------|-------|",
    ]
    parts.extend(_family_finding_row(finding, source) for finding in findings[:max_findings])
    parts.extend(["", "### Family findings diagram", mermaid_family_findings_block(findings, source=source, max_findings=max_findings), ""])
    return "\n".join(parts)


def format_multi_plane_campaign_section(planes: list[dict], *, campaign: str = "Wave multi-plane", max_planes: int = 12) -> str:
    """Markdown section summarizing multi-plane red/blue campaign themes."""
    if not planes:
        return f"## {campaign} campaign\n\n_No multi-plane themes provided._\n"
    parts = [
        f"## {campaign} campaign", "",
        "> **Path-to-impact narrative:** each plane pairs red assess findings with blue harden/detect controls. Diagrams below are engagement ranking aids - not auto-exploit chains.", "",
        "| Plane | Stage | Red findings | Blue controls |", "|-------|-------|--------------|---------------|",
    ]
    mermaid_nodes: list[dict] = []
    for plane in planes[:max_planes]:
        row, nodes = _campaign_plane_row(plane)
        parts.append(row)
        mermaid_nodes.extend(nodes)
    parts.extend(["", "### Multi-plane family diagram", mermaid_family_findings_block(mermaid_nodes, max_findings=max_planes * 2), ""])
    return "\n".join(parts)


def _campaign_plane_row(plane: dict) -> tuple[str, list[dict]]:
    plane_id = str(plane.get("id") or plane.get("title") or "?")
    title = str(plane.get("title") or plane_id).replace("|", "/")
    stage = str(plane.get("stage") or "posture")
    red_ids = plane.get("red_ids") or []
    blue_ids = plane.get("blue_ids") or []
    row = f"| {title} | {stage} | {_finding_id_list(red_ids)} | {_finding_id_list(blue_ids)} |"
    return row, _campaign_plane_nodes(red_ids, blue_ids)


def _finding_id_list(finding_ids: list[object]) -> str:
    return ", ".join(f"`{item}`" for item in finding_ids[:3]) or " - "


def _campaign_plane_nodes(red_ids: list[object], blue_ids: list[object]) -> list[dict]:
    return [
        *(_family_node(item, "rootstock-red", str(item).split(".")[-1]) for item in red_ids[:2]),
        *(_family_node(item, "rootstock-blue", str(item)) for item in blue_ids[:2]),
    ]


def _family_node(finding_id: object, source: str, name: str) -> dict:
    return {"finding_id": finding_id, "name": name, "severity": "medium", "source": source}


def format_multi_plane_severity_board(findings: list[dict], *, title: str = "Multi-plane severity board", max_items: int = 16) -> str:
    """Compact severity board for red/blue multi-plane findings in reports."""
    if not findings:
        return f"## {title}\n\n_No findings._\n"
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda finding: order.get(str(finding.get("severity", "info")).lower(), 9))
    parts = [
        f"## {title}", "",
        "> Ranked for purple operators: red path-to-impact first within severity bands; blue harden/detect second. Not an auto-exploit queue.", "",
        "| Sev | Side | ID | Title |", "|-----|------|----|-------|",
    ]
    parts.extend(_severity_board_row(finding) for finding in sorted_findings[:max_items])
    parts.extend(["", mermaid_family_findings_block(sorted_findings[:max_items]), ""])
    return "\n".join(parts)


def _severity_board_row(finding: dict) -> str:
    finding_id = _family_finding_id(finding)
    name = str(finding.get("name") or finding.get("title") or finding_id).replace("|", "/")
    severity = str(finding.get("severity") or "info")
    side = "red" if is_red_family_finding(finding, finding_id, None) else "blue"
    return f"| {severity} | {side} | `{finding_id}` | {name} |"


def format_purple_engagement_matrix(pairs: list[dict], *, title: str = "Purple engagement matrix", max_pairs: int = 20) -> str:
    """Render the red-finding to blue-control engagement matrix."""
    if not pairs:
        return f"## {title}\n\n_No red↔blue pairs provided._\n"
    parts = [
        f"## {title}", "",
        "> **Purple operator view:** map red path-to-impact findings to blue offline parse/harden/detect controls. Assess-first - not auto-exploit.", "",
        "| Plane | Stage | Red assess ID | Blue defend ID |", "|-------|-------|---------------|----------------|",
    ]
    findings: list[dict] = []
    for pair in pairs[:max_pairs]:
        row, pair_findings = _engagement_pair_row(pair)
        parts.append(row)
        findings.extend(pair_findings)
    parts.extend(["", "### Engagement matrix diagram", mermaid_family_findings_block(findings, max_findings=max_pairs * 2), ""])
    return "\n".join(parts)


def _engagement_pair_row(pair: dict) -> tuple[str, list[dict]]:
    plane = str(pair.get("plane") or pair.get("title") or "?").replace("|", "/")
    stage = str(pair.get("stage") or "posture")
    red = str(pair.get("red_id") or "")
    blue = str(pair.get("blue_id") or "")
    return f"| {plane} | {stage} | `{red}` | `{blue}` |", _engagement_findings(red, blue)


def _engagement_findings(red: str, blue: str) -> list[dict]:
    findings: list[dict] = []
    if red:
        findings.append(_family_node(red, "rootstock-red", red.split(".")[-1]))
    if blue:
        finding_id = blue if blue.startswith("harden.") else f"harden.{blue}"
        findings.append(_family_node(finding_id, "rootstock-blue", blue))
    return findings


def format_kill_chain_stage_timeline(stages: list[dict], *, title: str = "Kill-chain stage timeline", max_stages: int = 12) -> str:
    """Mermaid timeline of multi-plane engagement stages for purple reports."""
    if not stages:
        return f"## {title}\n\n_No stages provided._\n"
    parts = [f"## {title}", "", "> **Path-to-impact narrative only** - stage labels rank operator attention, not automated exploit orchestration.", "", "```mermaid", "timeline", f"    title {title}"]
    parts.extend(_timeline_mermaid_row(stage) for stage in stages[:max_stages])
    parts.extend(["```", "", "| Stage | Red findings | Blue controls | Notes |", "|-------|--------------|---------------|-------|"])
    parts.extend(_timeline_table_row(stage) for stage in stages[:max_stages])
    parts.append("")
    return "\n".join(parts)


def _timeline_mermaid_row(stage: dict) -> str:
    name = str(stage.get("stage") or stage.get("name") or "stage")
    label = str(stage.get("label") or name)
    red_count = stage.get("red_count", "")
    blue_count = stage.get("blue_count", "")
    detail = f"{label} (R:{red_count} B:{blue_count})" if red_count != "" or blue_count != "" else label
    return f"    {name} : {detail}"


def _timeline_table_row(stage: dict) -> str:
    name = str(stage.get("stage") or "?")
    red_count = stage.get("red_count", " - ")
    blue_count = stage.get("blue_count", " - ")
    notes = str(stage.get("label") or stage.get("notes") or "").replace("|", "/")
    return f"| {name} | {red_count} | {blue_count} | {notes} |"


def format_fleet_campaign_dashboard(campaigns: list[dict], *, title: str = "Fleet multi-plane campaign dashboard") -> str:
    """Aggregate dashboard for multi-wave red/blue half-pair campaigns."""
    if not campaigns:
        return f"## {title}\n\n_No campaigns provided._\n"
    total_themes = sum(int(campaign.get("theme_count") or 0) for campaign in campaigns)
    total_half = sum(int(campaign.get("half_pairs") or 0) for campaign in campaigns)
    parts = [f"## {title}", "", f"> **Campaign fleet:** {len(campaigns)} waves · {total_themes} multi-plane themes · {total_half} red|blue half-pairs. Assess-first path-to-impact - not auto-exploit.", "", "| Campaign | Themes | Half-pairs | Stages | Highlight |", "|----------|--------|------------|--------|-----------|"]
    findings: list[dict] = []
    for campaign in campaigns:
        row, finding = _fleet_campaign_row(campaign)
        parts.append(row)
        findings.append(finding)
    parts.extend(["", "### Fleet diagram", mermaid_family_findings_block(findings, max_findings=max(len(campaigns) * 2, 8)), ""])
    return "\n".join(parts)


def _fleet_campaign_row(campaign: dict) -> tuple[str, dict]:
    name = str(campaign.get("name") or "?")
    themes = campaign.get("theme_count", " - ")
    half_pairs = campaign.get("half_pairs", " - ")
    stages = ", ".join(campaign.get("stages") or []) or " - "
    highlight = str(campaign.get("highlight") or "").replace("|", "/")
    row = f"| {name} | {themes} | {half_pairs} | {stages} | {highlight} |"
    finding = {"finding_id": f"campaign.{name}", "name": name, "severity": "high" if int(campaign.get("theme_count") or 0) >= 20 else "medium", "source": "rootstock-red" if "Wave" in name else "rootstock-blue"}
    return row, finding
