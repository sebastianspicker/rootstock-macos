import Foundation

/// SQLite schema v0 for `.rsbcase/case.sqlite`.
public enum CaseSchema {
    public static let version = 0

    public static let createStatements: [String] = [
        """
        CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS sources (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            path TEXT,
            collected_at TEXT,
            notes TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS processes (
            entity_id TEXT PRIMARY KEY,
            pid INTEGER,
            path TEXT,
            signing_id TEXT,
            team_id TEXT,
            first_seen TEXT,
            last_seen TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS file_events (
            id TEXT PRIMARY KEY,
            event_time TEXT,
            path TEXT,
            process_entity_id TEXT,
            action TEXT,
            source_plugin TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS timeline_events (
            id TEXT PRIMARY KEY,
            event_time TEXT NOT NULL,
            collected_at TEXT,
            source TEXT,
            source_plugin TEXT,
            event_type TEXT,
            summary TEXT,
            entity_refs TEXT,
            fields_json TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            title TEXT,
            severity TEXT,
            event_ids TEXT,
            attack_techniques TEXT,
            evidence_summary TEXT,
            created_at TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS persistence_items (
            id TEXT PRIMARY KEY,
            kind TEXT,
            path TEXT,
            label TEXT,
            user_context TEXT,
            source_plugin TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS tcc_entries (
            id TEXT PRIMARY KEY,
            service TEXT,
            client TEXT,
            auth_value TEXT,
            source_plugin TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS custody_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            actor TEXT,
            action TEXT,
            detail TEXT
        );
        """,
    ]
}
