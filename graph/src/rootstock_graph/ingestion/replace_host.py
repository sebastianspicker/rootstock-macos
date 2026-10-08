"""replace_host.py - Remove earlier scans of a host before re-importing it.

Application, Computer and TCC identity is scan-scoped (the scan_id is part of the
node key), so re-importing a host would otherwise leave the earlier scan's graph
next to the new one and every finding would appear twice. Replacing earlier scans
of the same Mac is therefore the default; ``--keep-previous-scans`` opts out
for operators who want history side by side. ``--replace-host`` is accepted for
compatibility and is a no-op.

An earlier scan belongs to the same Mac when its Computer has the same hostname and
the same ``hardware_uuid`` (or both scans lack one). Hostnames such as
``MacBook-Pro.local`` collide between machines, so an earlier scan with the same
hostname but a different hardware UUID is kept and a warning names it.

Caveat: every node carrying a ``scan_id`` of an earlier scan of the same Mac
is removed, including nodes that were shared with other hosts' scans through that
scan_id. Nodes without a ``scan_id`` are never touched.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Mapping

from neo4j import Session

__all__ = [
    "add_replace_host_arg",
    "previous_scan_ids",
    "replace_host_requested",
    "replace_host_scans",
    "split_previous_scans",
]

_DELETE_BATCH_SIZE = 1000


def add_replace_host_arg(parser) -> None:
    parser.add_argument(
        "--replace-host",
        action="store_true",
        help="Accepted for compatibility; replacing earlier scans of the host is the default.",
    )
    parser.add_argument(
        "--keep-previous-scans",
        action="store_true",
        help=(
            "Keep earlier scans of the same Mac (hostname and hardware UUID) in the graph "
            "instead of deleting them "
            "before this import (every finding then appears once per scan)"
        ),
    )


def replace_host_requested(args) -> bool:
    """True unless the operator asked to keep earlier scans."""
    return not getattr(args, "keep_previous_scans", False)


def split_previous_scans(
    rows: Iterable[Mapping[str, object]], hardware_uuid: str | None
) -> tuple[list[str], list[str]]:
    """Split earlier scans of a hostname into (same Mac, other Mac) scan_ids.

    A row is the same Mac when its ``hardware_uuid`` equals ``hardware_uuid``, or both
    are null. Rows with the same hostname but a different UUID are another Mac.
    """
    same: list[str] = []
    other: list[str] = []
    for row in rows:
        scan_id = str(row["scan_id"])
        target = same if row.get("hardware_uuid") == hardware_uuid else other
        if scan_id not in target:
            target.append(scan_id)
    return same, other


def previous_scan_ids(
    session: Session, hostname: str, scan_id: str, hardware_uuid: str | None = None
) -> list[str]:
    """Return scan_ids of earlier Computer nodes of the same Mac (see module docstring).

    Earlier scans with this hostname but a different hardware UUID are kept; a warning
    naming each of them is printed to stderr.
    """
    result = session.run(
        """
        MATCH (c:Computer {hostname: $hostname})
        WHERE c.scan_id IS NOT NULL AND c.scan_id <> $scan_id
        RETURN c.scan_id AS scan_id, c.hardware_uuid AS hardware_uuid
        ORDER BY scan_id
        """,
        hostname=hostname,
        scan_id=scan_id,
    )
    same, other = split_previous_scans(result, hardware_uuid)
    for other_scan in other:
        print(
            f"  Warning: keeping scan {other_scan}: hostname {hostname!r} matches but the "
            "hardware UUID differs (another Mac with the same name)",
            file=sys.stderr,
        )
    return same


def replace_host_scans(
    session: Session, hostname: str, scan_id: str, hardware_uuid: str | None = None
) -> int:
    """Detach-delete all nodes of earlier scans of this Mac. Returns nodes removed."""
    scan_ids = previous_scan_ids(session, hostname, scan_id, hardware_uuid)
    if not scan_ids:
        return 0

    # Relationships between global nodes (MEMBER_OF, SUDO_NOPASSWD, ACCESSIBLE_BY)
    # carry the scan_id on the edge, so they are removed first.
    _delete_in_batches(
        session,
        """
        MATCH ()-[r]->()
        WHERE r.scan_id IN $scan_ids
        WITH r LIMIT $batch_size
        DELETE r
        RETURN count(*) AS n
        """,
        scan_ids,
    )
    return _delete_in_batches(
        session,
        """
        MATCH (n)
        WHERE n.scan_id IN $scan_ids
        WITH n LIMIT $batch_size
        DETACH DELETE n
        RETURN count(*) AS n
        """,
        scan_ids,
    )


def _delete_in_batches(session: Session, statement: str, scan_ids: list[str]) -> int:
    removed = 0
    while True:
        result = session.run(statement, scan_ids=scan_ids, batch_size=_DELETE_BATCH_SIZE)
        batch = result.single()["n"]
        if batch == 0:
            return removed
        removed += batch
