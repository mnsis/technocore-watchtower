"""SQLite persistence for minimized event metadata."""

import json
import sqlite3
from pathlib import Path

from .models import SecurityEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    observed_at TEXT NOT NULL,
    message_timestamp TEXT NOT NULL,
    room TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    sender_name TEXT NOT NULL,
    did TEXT,
    did_present INTEGER NOT NULL CHECK (did_present IN (0, 1)),
    signed_identity_present INTEGER NOT NULL CHECK (signed_identity_present IN (0, 1)),
    flags_json TEXT NOT NULL,
    severity TEXT NOT NULL,
    message_sha256 TEXT NOT NULL CHECK (length(message_sha256) = 64),
    UNIQUE (room, sequence)
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(message_timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
"""


class EventStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.executescript(SCHEMA)

    def insert(self, event: SecurityEvent) -> bool:
        """Insert an event, returning False for an existing room/sequence."""

        with sqlite3.connect(self.path) as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO events (
                    observed_at, message_timestamp, room, sequence, sender_name,
                    did, did_present, signed_identity_present, flags_json,
                    severity, message_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.created_at.isoformat(),
                    event.message.timestamp.isoformat(),
                    event.message.room,
                    event.message.sequence,
                    event.message.sender_name,
                    event.message.did,
                    int(bool(event.message.did and event.message.did.startswith("did:key:"))),
                    int(event.message.signed_identity_present),
                    json.dumps([flag.value for flag in event.flags]),
                    event.severity.name,
                    event.message_sha256,
                ),
            )
            return cursor.rowcount == 1

    def dashboard_summary(self) -> dict[str, int | str | None]:
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """SELECT
                    count(*) AS total,
                    coalesce(sum(did_present), 0) AS did_present,
                    coalesce(sum(CASE WHEN did_present = 0 AND signed_identity_present = 0 THEN 1 ELSE 0 END), 0) AS unsigned,
                    coalesce(sum(CASE WHEN severity IN ('MEDIUM', 'HIGH') THEN 1 ELSE 0 END), 0) AS warnings,
                    max(sequence) AS last_sequence,
                    count(DISTINCT room) AS observed_rooms
                FROM events"""
            ).fetchone()
        return dict(row) if row is not None else {}

    def recent_events(self, limit: int = 100) -> list[dict[str, object]]:
        limit = max(1, min(limit, 500))
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """SELECT id, observed_at, message_timestamp, room, sequence,
                    sender_name, did, did_present, signed_identity_present,
                    flags_json, severity, message_sha256
                FROM events ORDER BY message_timestamp DESC, id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [self._event_row(row) for row in rows]

    def event_by_id(self, event_id: int) -> dict[str, object] | None:
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """SELECT id, observed_at, message_timestamp, room, sequence,
                    sender_name, did, did_present, signed_identity_present,
                    flags_json, severity, message_sha256
                FROM events WHERE id = ?""",
                (event_id,),
            ).fetchone()
        return self._event_row(row) if row is not None else None

    def observed_rooms(self) -> list[dict[str, object]]:
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """SELECT room, max(sequence) AS last_sequence,
                    max(message_timestamp) AS last_seen, count(*) AS observations,
                    sum(CASE WHEN severity IN ('MEDIUM', 'HIGH') THEN 1 ELSE 0 END) AS warnings
                FROM events GROUP BY room ORDER BY room"""
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _event_row(row: sqlite3.Row) -> dict[str, object]:
        data = dict(row)
        data["flags"] = json.loads(str(data.pop("flags_json")))
        if data["signed_identity_present"]:
            data["identity_status"] = "SIGNED METADATA PRESENT"
        elif data["did_present"]:
            data["identity_status"] = "DID PRESENT"
        else:
            data["identity_status"] = "UNSIGNED"
        return data
