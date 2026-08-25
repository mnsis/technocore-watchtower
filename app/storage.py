"""SQLite persistence for minimized event metadata."""

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import SecurityEvent, SecurityFlag

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
CREATE INDEX IF NOT EXISTS idx_events_observed_at ON events(observed_at);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
"""

REPORT_FLAGS = (
    "UNSIGNED_PRIVILEGED_NAME",
    "POTENTIAL_TECHNOCORE_WRITE_URL",
    "SUSPICIOUS_COMBINATION",
)
SEVERITY_NAMES = ("HIGH", "MEDIUM", "LOW", "INFO", "NONE")
SECURITY_FLAG_NAMES = tuple(flag.value for flag in SecurityFlag)


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
                    coalesce(sum(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0) AS high_risk,
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

    def filtered_events(
        self,
        *,
        room: str | None = None,
        severity: str | None = None,
        flag: str | None = None,
        limit: int = 50,
        before_id: int | None = None,
    ) -> tuple[list[dict[str, object]], int | None]:
        """Return a cursor page for the metadata-only dashboard event table."""

        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if severity is not None and severity not in SEVERITY_NAMES:
            raise ValueError("unknown severity")
        if flag is not None and flag not in SECURITY_FLAG_NAMES:
            raise ValueError("unknown security flag")
        if before_id is not None and before_id <= 0:
            raise ValueError("before_id must be positive")

        clauses: list[str] = []
        parameters: list[object] = []
        if room is not None:
            clauses.append("room = ?")
            parameters.append(room)
        if severity is not None:
            clauses.append("severity = ?")
            parameters.append(severity)
        if flag is not None:
            clauses.append(
                "EXISTS (SELECT 1 FROM json_each(events.flags_json) WHERE value = ?)"
            )
            parameters.append(flag)
        if before_id is not None:
            clauses.append("id < ?")
            parameters.append(before_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        parameters.append(limit + 1)

        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """SELECT id, observed_at, message_timestamp, room, sequence,
                    sender_name, did, did_present, signed_identity_present,
                    flags_json, severity, message_sha256
                FROM events"""
                + where
                + " ORDER BY id DESC LIMIT ?",
                parameters,
            ).fetchall()

        has_more = len(rows) > limit
        selected = rows[:limit]
        events = [self._event_row(row) for row in selected]
        next_before_id = int(selected[-1]["id"]) if has_more and selected else None
        return events, next_before_id

    def dashboard_charts(
        self, hours: int = 24, *, generated_at: datetime | None = None
    ) -> dict[str, object]:
        """Return read-only chart aggregates without changing storage semantics."""

        if hours != 24:
            raise ValueError("dashboard charts currently use a 24-hour window")
        selected_time = (generated_at or datetime.now(UTC)).astimezone(UTC)
        end_hour = selected_time.replace(minute=0, second=0, microsecond=0)
        start = end_hour - timedelta(hours=24)
        bucket_seconds = 4 * 60 * 60
        bounds = (start.isoformat(), selected_time.isoformat())

        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            time_rows = connection.execute(
                """SELECT
                    (CAST(strftime('%s', observed_at) AS INTEGER) / ?) * ? AS bucket,
                    count(*) AS observations
                FROM events
                WHERE observed_at >= ? AND observed_at <= ?
                GROUP BY bucket ORDER BY bucket""",
                (bucket_seconds, bucket_seconds, *bounds),
            ).fetchall()

        by_bucket = {int(row["bucket"]): int(row["observations"]) for row in time_rows}
        series = []
        for offset in range(0, 25, 4):
            point = start + timedelta(hours=offset)
            epoch = int(point.timestamp()) // bucket_seconds * bucket_seconds
            series.append({"label": point.strftime("%H:%M"), "value": by_bucket.get(epoch, 0)})

        report = self.security_report(hours, generated_at=selected_time)
        severity = report["severity"]
        assert isinstance(severity, dict)
        return {
            "period_hours": hours,
            "observations": series,
            "severity": [
                {"label": name.upper(), "value": int(severity[name])}
                for name in ("high", "medium", "low", "info", "none")
            ],
            "top_flagged_rooms": report["top_flagged_rooms"],
        }

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

    def api_events(
        self,
        *,
        room: str | None = None,
        severity: str | None = None,
        flag: str | None = None,
        limit: int = 50,
        before_id: int | None = None,
    ) -> tuple[list[dict[str, object]], int | None]:
        """Return a cursor page of metadata-only events for the read-only API."""

        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        if severity is not None and severity not in SEVERITY_NAMES:
            raise ValueError("unknown severity")
        if flag is not None and flag not in SECURITY_FLAG_NAMES:
            raise ValueError("unknown security flag")
        if before_id is not None and before_id <= 0:
            raise ValueError("before_id must be positive")

        clauses: list[str] = []
        parameters: list[object] = []
        if room is not None:
            clauses.append("room = ?")
            parameters.append(room)
        if severity is not None:
            clauses.append("severity = ?")
            parameters.append(severity)
        if flag is not None:
            clauses.append(
                "EXISTS (SELECT 1 FROM json_each(events.flags_json) WHERE value = ?)"
            )
            parameters.append(flag)
        if before_id is not None:
            clauses.append("id < ?")
            parameters.append(before_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        parameters.append(limit + 1)

        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """SELECT id, message_timestamp, room, sequence, sender_name,
                    did, signed_identity_present, severity, flags_json,
                    message_sha256
                FROM events"""
                + where
                + " ORDER BY id DESC LIMIT ?",
                parameters,
            ).fetchall()

        has_more = len(rows) > limit
        selected = rows[:limit]
        events = [self._api_event_row(row) for row in selected]
        next_before_id = int(selected[-1]["id"]) if has_more and selected else None
        return events, next_before_id

    def api_event_by_room_sequence(
        self, room: str, sequence: int
    ) -> dict[str, object] | None:
        """Return one persisted metadata event in the public API shape."""

        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """SELECT id, message_timestamp, room, sequence, sender_name,
                    did, signed_identity_present, severity, flags_json,
                    message_sha256
                FROM events WHERE room = ? AND sequence = ?""",
                (room, sequence),
            ).fetchone()
        return self._api_event_row(row) if row is not None else None

    def latest_event_id(self) -> int:
        """Return the latest persisted event id for stream snapshot coordination."""

        with sqlite3.connect(self.path) as connection:
            row = connection.execute("SELECT coalesce(max(id), 0) FROM events").fetchone()
        return int(row[0]) if row is not None else 0

    def api_room_summaries(self, room: str | None = None) -> list[dict[str, object]]:
        """Return aggregate metadata for all observed rooms or one room."""

        parameters: tuple[object, ...] = () if room is None else (room,)
        where = "" if room is None else " WHERE room = ?"
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """SELECT
                    room,
                    count(*) AS observations,
                    coalesce(sum(CASE WHEN EXISTS (
                        SELECT 1 FROM json_each(events.flags_json)
                        WHERE value IN (
                            'UNSIGNED_PRIVILEGED_NAME',
                            'POTENTIAL_TECHNOCORE_WRITE_URL',
                            'SUSPICIOUS_COMBINATION'
                        )
                    ) THEN 1 ELSE 0 END), 0) AS flagged_events,
                    max(sequence) AS last_sequence,
                    max(message_timestamp) AS last_seen,
                    coalesce(sum(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0) AS high,
                    coalesce(sum(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END), 0) AS medium,
                    coalesce(sum(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END), 0) AS low,
                    coalesce(sum(CASE WHEN severity = 'INFO' THEN 1 ELSE 0 END), 0) AS info,
                    coalesce(sum(CASE WHEN severity = 'NONE' THEN 1 ELSE 0 END), 0) AS none
                FROM events"""
                + where
                + " GROUP BY room ORDER BY room",
                parameters,
            ).fetchall()
        return [
            {
                "room": row["room"],
                "observations": row["observations"],
                "flagged_events": row["flagged_events"],
                "last_sequence": row["last_sequence"],
                "last_seen": row["last_seen"],
                "severity": {
                    name.casefold(): row[name.casefold()] for name in SEVERITY_NAMES
                },
            }
            for row in rows
        ]

    def security_report(
        self, hours: int = 24, *, generated_at: datetime | None = None
    ) -> dict[str, object]:
        """Aggregate metadata-only security telemetry for a UTC time window."""

        if isinstance(hours, bool) or not isinstance(hours, int) or hours <= 0:
            raise ValueError("hours must be a positive integer")
        selected_time = generated_at or datetime.now(UTC)
        if selected_time.tzinfo is None or selected_time.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        selected_time = selected_time.astimezone(UTC)
        cutoff = selected_time - timedelta(hours=hours)
        bounds = (cutoff.isoformat(), selected_time.isoformat())

        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            aggregate = connection.execute(
                """SELECT
                    count(*) AS observations,
                    count(DISTINCT room) AS rooms_observed,
                    coalesce(sum(signed_identity_present), 0) AS signed_identity_present,
                    coalesce(sum(CASE WHEN signed_identity_present = 0 THEN 1 ELSE 0 END), 0) AS unsigned,
                    coalesce(sum(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0) AS high,
                    coalesce(sum(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END), 0) AS medium,
                    coalesce(sum(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END), 0) AS low,
                    coalesce(sum(CASE WHEN severity = 'INFO' THEN 1 ELSE 0 END), 0) AS info,
                    coalesce(sum(CASE WHEN severity = 'NONE' THEN 1 ELSE 0 END), 0) AS none,
                    coalesce(sum(CASE WHEN EXISTS (
                        SELECT 1 FROM json_each(events.flags_json)
                        WHERE value = 'UNSIGNED_PRIVILEGED_NAME'
                    ) THEN 1 ELSE 0 END), 0) AS unsigned_privileged_name,
                    coalesce(sum(CASE WHEN EXISTS (
                        SELECT 1 FROM json_each(events.flags_json)
                        WHERE value = 'POTENTIAL_TECHNOCORE_WRITE_URL'
                    ) THEN 1 ELSE 0 END), 0) AS potential_write_urls,
                    coalesce(sum(CASE WHEN EXISTS (
                        SELECT 1 FROM json_each(events.flags_json)
                        WHERE value = 'SUSPICIOUS_COMBINATION'
                    ) THEN 1 ELSE 0 END), 0) AS suspicious_combination
                FROM events
                WHERE observed_at >= ? AND observed_at <= ?""",
                bounds,
            ).fetchone()
            top_rooms = connection.execute(
                """SELECT room, count(*) AS events
                FROM events
                WHERE observed_at >= ? AND observed_at <= ?
                  AND EXISTS (
                    SELECT 1 FROM json_each(events.flags_json)
                    WHERE value IN (
                        'UNSIGNED_PRIVILEGED_NAME',
                        'POTENTIAL_TECHNOCORE_WRITE_URL',
                        'SUSPICIOUS_COMBINATION'
                    )
                  )
                GROUP BY room
                ORDER BY events DESC, room ASC
                LIMIT 5""",
                bounds,
            ).fetchall()

        values = dict(aggregate) if aggregate is not None else {}
        return {
            "period_hours": hours,
            "generated_at": selected_time.isoformat().replace("+00:00", "Z"),
            "observations": int(values.get("observations", 0)),
            "rooms_observed": int(values.get("rooms_observed", 0)),
            "identity": {
                "signed_identity_present": int(
                    values.get("signed_identity_present", 0)
                ),
                "unsigned": int(values.get("unsigned", 0)),
                "unsigned_privileged_name": int(
                    values.get("unsigned_privileged_name", 0)
                ),
            },
            "url_safety": {
                "potential_write_urls": int(values.get("potential_write_urls", 0))
            },
            "severity": {
                name: int(values.get(name, 0))
                for name in ("high", "medium", "low", "info", "none")
            },
            "flags": {
                "UNSIGNED_PRIVILEGED_NAME": int(
                    values.get("unsigned_privileged_name", 0)
                ),
                "POTENTIAL_TECHNOCORE_WRITE_URL": int(
                    values.get("potential_write_urls", 0)
                ),
                "SUSPICIOUS_COMBINATION": int(
                    values.get("suspicious_combination", 0)
                ),
            },
            "top_flagged_rooms": [dict(row) for row in top_rooms],
        }

    def did_present_count(
        self, hours: int = 24, *, generated_at: datetime | None = None
    ) -> int:
        """Count DID-present metadata for the API summary time window."""

        if isinstance(hours, bool) or not isinstance(hours, int) or hours <= 0:
            raise ValueError("hours must be a positive integer")
        selected_time = generated_at or datetime.now(UTC)
        if selected_time.tzinfo is None or selected_time.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        selected_time = selected_time.astimezone(UTC)
        cutoff = selected_time - timedelta(hours=hours)
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                """SELECT coalesce(sum(did_present), 0)
                FROM events WHERE observed_at >= ? AND observed_at <= ?""",
                (cutoff.isoformat(), selected_time.isoformat()),
            ).fetchone()
        return int(row[0]) if row is not None else 0

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

    @staticmethod
    def _api_event_row(row: sqlite3.Row) -> dict[str, object]:
        return {
            "id": row["id"],
            "timestamp": row["message_timestamp"],
            "room": row["room"],
            "sequence": row["sequence"],
            "sender": row["sender_name"],
            "did": row["did"],
            "signed_identity_present": bool(row["signed_identity_present"]),
            "severity": row["severity"],
            "flags": json.loads(row["flags_json"]),
            "message_hash": row["message_sha256"],
        }
