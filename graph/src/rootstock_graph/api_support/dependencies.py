"""Neo4j session dependencies and request limits shared by the API routes."""

from __future__ import annotations

import logging

from fastapi import Depends, Request
from neo4j import READ_ACCESS

logger = logging.getLogger("rootstock.api")
MAX_ADHOC_CYPHER_LENGTH = 10_000
MAX_ADHOC_CYPHER_ROWS = 1_000
ADHOC_CYPHER_TIMEOUT_SECONDS = 5.0


def get_session(request: Request):
    """Yield a mutation-capable session from the writer principal."""
    with request.app.state.writer_driver.session() as session:
        yield session


def get_read_session(request: Request):
    """Yield a read-routed session from the distinct read-only principal."""
    with request.app.state.read_driver.session(default_access_mode=READ_ACCESS) as session:
        yield session


SESSION_DEPENDENCY = Depends(get_session)
READ_SESSION_DEPENDENCY = Depends(get_read_session)
