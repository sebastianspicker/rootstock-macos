"""
create_fixtures.py — Generate synthetic TCC.db fixtures for testing.

Creates four SQLite databases in the same directory:
  basic.db        — 10 grants (mix of allowed/denied, FDA/Camera/Mic/Accessibility)
  empty.db        — valid TCC schema, zero rows
  system-scope.db — entries with system scope (auth_reason=5 / MDM) and mixed services
  malformed.db    — wrong schema (missing columns) → tests graceful failure

Usage:
    python3 tests/fixtures/tcc/create_fixtures.py
"""

import sqlite3
from pathlib import Path

HERE = Path(__file__).parent

# Minimal schema matching the columns the Swift TCCDataSource actually queries.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS access (
    service TEXT NOT NULL,
    client  TEXT NOT NULL,
    client_type  INTEGER NOT NULL,
    auth_value   INTEGER NOT NULL,
    auth_reason  INTEGER NOT NULL,
    last_modified INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (service, client, client_type)
)
"""

# auth_value codes
ALLOW   = 2
DENY    = 0
LIMITED = 3

# auth_reason codes
USER  = 2   # user granted interactively
MDM   = 5   # MDM policy

_BASIC_ROWS = [
    # (service, client, client_type, auth_value, auth_reason, last_modified)
    ("kTCCServiceSystemPolicyAllFiles",  "com.googlecode.iterm2",       0, ALLOW,  USER, 1710748800),
    ("kTCCServiceAccessibility",         "com.googlecode.iterm2",       0, ALLOW,  USER, 1710748800),
    ("kTCCServiceCamera",                "com.tinyspeck.slackmacgap",   0, ALLOW,  USER, 1710748801),
    ("kTCCServiceMicrophone",            "com.tinyspeck.slackmacgap",   0, ALLOW,  USER, 1710748802),
    ("kTCCServiceScreenCapture",         "com.tinyspeck.slackmacgap",   0, DENY,   USER, 1710748803),
    ("kTCCServiceContacts",              "com.apple.AddressBook",       0, ALLOW,  USER, 1710748804),
    ("kTCCServiceCalendar",              "com.apple.Calendar",          0, ALLOW,  USER, 1710748805),
    ("kTCCServicePhotos",                "com.apple.Photos",            0, ALLOW,  USER, 1710748806),
    ("kTCCServiceLocation",              "com.apple.Maps",              0, LIMITED,USER, 1710748807),
    ("kTCCServiceAppleEvents",           "com.apple.Terminal",          0, DENY,   USER, 1710748808),
]

_SYSTEM_SCOPE_ROWS = [
    # system-level grants with MDM auth_reason
    ("kTCCServiceSystemPolicyAllFiles",  "com.example.edr.agent",        0, ALLOW, MDM, 1710748900),
    ("kTCCServiceMicrophone",            "com.example.meeting.client",   0, ALLOW, MDM, 1710748901),
    ("kTCCServiceCamera",                "com.example.security.scanner", 0, ALLOW, MDM, 1710748902),
    ("kTCCServiceAccessibility",         "com.example.remote.helper",    0, ALLOW, MDM, 1710748903),
]


def _create(path: Path, schema: str, rows: list[tuple]) -> None:
    path.unlink(missing_ok=True)
    con = sqlite3.connect(str(path))
    con.executescript(schema)
    if rows:
        con.executemany(
            "INSERT OR REPLACE INTO access "
            "(service, client, client_type, auth_value, auth_reason, last_modified) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
    con.commit()
    con.close()


def create_basic() -> None:
    _create(HERE / "basic.db", _SCHEMA, _BASIC_ROWS)
    print(f"  basic.db         — {len(_BASIC_ROWS)} grants")


def create_empty() -> None:
    _create(HERE / "empty.db", _SCHEMA, [])
    print("  empty.db         — 0 rows (valid schema)")


def create_system_scope() -> None:
    _create(HERE / "system-scope.db", _SCHEMA, _SYSTEM_SCOPE_ROWS)
    print(f"  system-scope.db  — {len(_SYSTEM_SCOPE_ROWS)} system-scope/MDM grants")


def create_malformed() -> None:
    """Create a DB with wrong schema — missing the 'auth_reason' column."""
    path = HERE / "malformed.db"
    path.unlink(missing_ok=True)
    con = sqlite3.connect(str(path))
    con.executescript("""
        CREATE TABLE IF NOT EXISTS access (
            service TEXT NOT NULL,
            client  TEXT NOT NULL,
            wrong_column INTEGER
        )
    """)
    con.execute("INSERT INTO access VALUES ('kTCCServiceCamera', 'com.example.app', 99)")
    con.commit()
    con.close()
    print("  malformed.db     — wrong schema (missing auth_value/auth_reason/last_modified)")


if __name__ == "__main__":
    print("Creating TCC fixture databases …")
    create_basic()
    create_empty()
    create_system_scope()
    create_malformed()
    print("Done.")
