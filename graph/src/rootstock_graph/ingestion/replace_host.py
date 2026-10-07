"""replace_host.py - Remove earlier scans of a host before re-importing it.

Application, Computer and TCC identity is scan-scoped (the scan_id is part of the
node key), so re-importing a host would otherwise leave the earlier scan's graph
next to the new one. This is opt-in via ``--replace-host``.

Caveat: every node carrying a ``scan_id`` of an earlier scan of the same hostname
is removed, including nodes that were shared with other hosts' scans through that
scan_id. Nodes without a ``scan_id`` are never touched.
"""

from __future__ import annotations

from neo4j import Session

__all__ = ["add_replace_host_arg", "previous_scan_ids", "replace_host_scans"]

_DELETE_BATCH_SIZE = 1000


def add_replace_host_arg(parser) -> None:
    parser.add_argument(
        "--replace-host",
        action="store_true",
        help=(
            "Before importing, delete every node from earlier scans of the same hostname "
            "(default: keep earlier scans alongside the new one)"
        ),
    )


def previous_scan_ids(session: Session, hostname: str, scan_id: str) -> list[str]:
    """Return scan_ids of Computer nodes for this hostname that differ from scan_id."""
    result = session.run(
        """
        MATCH (c:Computer {hostname: $hostname})
        WHERE c.scan_id IS NOT NULL AND c.scan_id <> $scan_id
        RETURN collect(DISTINCT c.scan_id) AS scan_ids
        """,
        hostname=hostname,
        scan_id=scan_id,
    )
    return list(result.single()["scan_ids"])


def replace_host_scans(session: Session, hostname: str, scan_id: str) -> int:
    """Detach-delete all nodes of earlier scans of this host. Returns nodes removed."""
    scan_ids = previous_scan_ids(session, hostname, scan_id)
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
