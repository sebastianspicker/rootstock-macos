"""Local-only and read-only validation for the Rootstock HTTP boundary."""

from __future__ import annotations

import hmac
import ipaddress
import re
from urllib.parse import SplitResult, urlsplit

from utils import cypher_code_only, validate_read_only_cypher

MIN_API_TOKEN_BYTES = 32
_CALL_RE = re.compile(r"\bCALL\b", re.IGNORECASE)


def matches_api_token(auth_header: str, token: str | None) -> bool:
    """Check the expected bearer header without exposing token timing."""
    scheme, separator, presented = auth_header.partition(" ")
    return (
        bool(token)
        and separator == " "
        and scheme == "Bearer"
        and hmac.compare_digest(presented.encode(), token.encode())
    )


def validate_adhoc_cypher(cypher: str) -> str | None:
    return validate_api_cypher(cypher)


def validate_api_cypher(cypher: str) -> str | None:
    """Apply the viewer API's stricter no-procedure read-only policy."""
    cleaned = cypher_code_only(cypher)
    if _CALL_RE.search(cleaned):
        return "Procedures are not allowed through the viewer API"
    return validate_read_only_cypher(cypher)


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_bind_host(host: str) -> None:
    """Reject every non-loopback bind for the alpha release surface."""
    if is_loopback_host(host):
        return
    raise ValueError("Refusing non-loopback bind; alpha is loopback-only")


def is_supported_neo4j_scheme(scheme: str) -> bool:
    return scheme in {"bolt", "neo4j", "bolt+s", "neo4j+s"}


def has_neo4j_uri_credentials(parsed: SplitResult) -> bool:
    return bool(parsed.username or parsed.password)


def has_loopback_neo4j_host(parsed: SplitResult) -> bool:
    return bool(parsed.hostname and is_loopback_host(parsed.hostname))


def has_neo4j_uri_suffix(parsed: SplitResult) -> bool:
    return bool(parsed.path not in {"", "/"} or parsed.query or parsed.fragment)


def validate_neo4j_uri(uri: str) -> None:
    """Keep the alpha server's outbound database connection on loopback."""
    parsed = urlsplit(uri)
    if not is_supported_neo4j_scheme(parsed.scheme):
        raise ValueError("Neo4j URI must use a supported Bolt/Neo4j scheme")
    if has_neo4j_uri_credentials(parsed):
        raise ValueError("Neo4j URI must not contain credentials")
    if not has_loopback_neo4j_host(parsed):
        raise ValueError("Refusing non-loopback Neo4j URI; alpha is local-only")
    if has_neo4j_uri_suffix(parsed):
        raise ValueError("Neo4j URI must not contain a path, query, or fragment")


def validate_api_token(token: str) -> None:
    if len(token.encode("utf-8")) < MIN_API_TOKEN_BYTES:
        raise ValueError(
            f"ROOTSTOCK_API_TOKEN must be at least {MIN_API_TOKEN_BYTES} bytes"
        )
