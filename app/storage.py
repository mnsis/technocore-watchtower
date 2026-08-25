"""SQLite persistence for minimized event metadata."""

import json
import logging
import math
import sqlite3
import statistics
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import SecurityEvent, SecurityFlag
from .risk import (
    BASELINE_WINDOW_HOURS,
    BURST_FLOOR_PER_MINUTE,
    ENGINE_VERSION,
    IDENTITY_WINDOW_HOURS,
    REPEAT_WINDOW_MINUTES,
    HistoricalContext,
    RiskEngine,
    RiskEvaluation,
    normalize_sender_name,
)

logger = logging.getLogger(__name__)

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
CREATE INDEX IF NOT EXISTS idx_events_did_timestamp ON events(did, message_timestamp);
CREATE INDEX IF NOT EXISTS idx_events_room_timestamp ON events(room, message_timestamp);
CREATE TABLE IF NOT EXISTS event_identity_metadata (
    event_id INTEGER PRIMARY KEY,
    normalized_sender_name TEXT NOT NULL,
    normalization_version TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_identity_name_event
    ON event_identity_metadata(normalized_sender_name, event_id);
CREATE TABLE IF NOT EXISTS risk_evaluations (
    event_id INTEGER NOT NULL,
    engine_version TEXT NOT NULL,
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    shadow_classification TEXT NOT NULL,
    evaluated_at TEXT NOT NULL,
    context_json TEXT NOT NULL,
    risk_families_json TEXT NOT NULL,
    temporal_corroboration INTEGER NOT NULL CHECK (temporal_corroboration IN (0, 1)),
    gate_explanation TEXT,
    PRIMARY KEY (event_id, engine_version),
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_risk_version_classification
    ON risk_evaluations(engine_version, shadow_classification);
CREATE TABLE IF NOT EXISTS event_signals (
    event_id INTEGER NOT NULL,
    engine_version TEXT NOT NULL,
    code TEXT NOT NULL,
    points INTEGER NOT NULL CHECK (points BETWEEN 0 AND 100),
    family TEXT NOT NULL,
    kind TEXT NOT NULL,
    PRIMARY KEY (event_id, engine_version, code),
    FOREIGN KEY (event_id, engine_version)
        REFERENCES risk_evaluations(event_id, engine_version) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_event_signals_code_event
    ON event_signals(engine_version, code, event_id);
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

    def insert(self, event: SecurityEvent, risk_engine: RiskEngine | None = None) -> bool:
        """Insert an event, returning False for an existing room/sequence."""

        with sqlite3.connect(self.path, timeout=10) as connection:
            observed_at = event.created_at.isoformat()
            cursor = connection.execute(
                """INSERT OR IGNORE INTO events (
                    observed_at, message_timestamp, room, sequence, sender_name,
                    did, did_present, signed_identity_present, flags_json,
                    severity, message_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    observed_at,
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
            if cursor.rowcount != 1:
                return False
            if cursor.lastrowid is None:
                raise RuntimeError("inserted event did not receive an id")
            event_id = cursor.lastrowid
            connection.execute("SAVEPOINT shadow_risk")
            try:
                engine = risk_engine or RiskEngine()
                self._evaluate_shadow_event(
                    connection,
                    event_id=event_id,
                    message_timestamp=event.message.timestamp.isoformat(),
                    room=event.message.room,
                    sequence=event.message.sequence,
                    sender_name=event.message.sender_name,
                    did=event.message.did,
                    did_present=bool(
                        event.message.did and event.message.did.startswith("did:key:")
                    ),
                    signed_identity_present=event.message.signed_identity_present,
                    write_capable_route=(
                        SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL in event.flags
                    ),
                    engine=engine,
                )
                connection.execute("RELEASE SAVEPOINT shadow_risk")
            except Exception:
                connection.execute("ROLLBACK TO SAVEPOINT shadow_risk")
                connection.execute("RELEASE SAVEPOINT shadow_risk")
                logger.exception("shadow risk evaluation failed; metadata insert retained")
            return True

    def _evaluate_shadow_event(
        self,
        connection: sqlite3.Connection,
        *,
        event_id: int,
        message_timestamp: str,
        room: str,
        sequence: int,
        sender_name: str,
        did: str | None,
        did_present: bool,
        signed_identity_present: bool,
        write_capable_route: bool,
        engine: RiskEngine,
    ) -> RiskEvaluation:
        normalized_name = normalize_sender_name(sender_name)
        connection.execute(
            """INSERT OR REPLACE INTO event_identity_metadata (
                event_id, normalized_sender_name, normalization_version
            ) VALUES (?, ?, ?)""",
            (event_id, normalized_name, engine.normalization_version),
        )
        evidence = engine.event_evidence(
            sender_name=sender_name,
            did_present=did_present,
            signed_identity_present=signed_identity_present,
            write_capable_route=write_capable_route,
        )
        signal_codes = engine.risk_signal_codes(evidence)
        context = self._historical_risk_context(
            connection,
            event_id=event_id,
            message_timestamp=message_timestamp,
            room=room,
            sequence=sequence,
            normalized_name=normalized_name,
            did=did,
            signal_codes=signal_codes,
            engine_version=engine.version,
        )
        evaluation = engine.evaluate(evidence, context)
        self._persist_shadow_evaluation(
            connection,
            event_id=event_id,
            evaluation=evaluation,
        )
        return evaluation

    @staticmethod
    def _prior_clause(alias: str = "e") -> str:
        return (
            f"{alias}.message_timestamp >= ? AND "
            f"({alias}.message_timestamp < ? OR "
            f"({alias}.message_timestamp = ? AND {alias}.id < ?))"
        )

    def _historical_risk_context(
        self,
        connection: sqlite3.Connection,
        *,
        event_id: int,
        message_timestamp: str,
        room: str,
        sequence: int,
        normalized_name: str,
        did: str | None,
        signal_codes: tuple[str, ...],
        engine_version: str,
    ) -> HistoricalContext:
        selected_time = datetime.fromisoformat(message_timestamp).astimezone(UTC)
        identity_cutoff = selected_time - timedelta(hours=IDENTITY_WINDOW_HOURS)
        signal_cutoff = selected_time - timedelta(minutes=REPEAT_WINDOW_MINUTES)
        minute_cutoff = selected_time - timedelta(minutes=1)
        baseline_cutoff = selected_time - timedelta(hours=BASELINE_WINDOW_HOURS)
        baseline_end = selected_time.replace(second=0, microsecond=0)

        prior_identity = self._prior_clause()
        prior_params = (message_timestamp, message_timestamp, event_id)
        prior_names: set[str] = set()
        if did is not None:
            prior_names = {
                str(row[0])
                for row in connection.execute(
                    """SELECT DISTINCT im.normalized_sender_name
                    FROM events e JOIN event_identity_metadata im ON im.event_id = e.id
                    WHERE e.did = ? AND """
                    + prior_identity,
                    (did, identity_cutoff.isoformat(), *prior_params),
                )
            }
        did_names = prior_names | ({normalized_name} if did is not None else set())

        prior_dids = {
            str(row[0])
            for row in connection.execute(
                """SELECT DISTINCT e.did
                FROM events e JOIN event_identity_metadata im ON im.event_id = e.id
                WHERE im.normalized_sender_name = ? AND e.did IS NOT NULL AND """
                + prior_identity,
                (normalized_name, identity_cutoff.isoformat(), *prior_params),
            )
        }
        name_dids = prior_dids | ({did} if did is not None else set())

        repeated_count = 0
        signal_room_count = 1 if signal_codes else 0
        if signal_codes:
            placeholders = ",".join("?" for _ in signal_codes)
            signal_rows = connection.execute(
                """SELECT s.code, count(*) AS occurrences,
                    count(DISTINCT e.room) AS rooms,
                    max(CASE WHEN e.room = ? THEN 1 ELSE 0 END) AS current_room_seen
                FROM event_signals s JOIN events e ON e.id = s.event_id
                WHERE s.engine_version = ? AND s.code IN ("""
                + placeholders
                + ") AND "
                + prior_identity
                + " GROUP BY s.code",
                (
                    room,
                    engine_version,
                    *signal_codes,
                    signal_cutoff.isoformat(),
                    *prior_params,
                ),
            ).fetchall()
            for row in signal_rows:
                repeated_count = max(repeated_count, int(row[1]))
                prior_rooms = int(row[2])
                current_seen = bool(row[3])
                signal_room_count = max(
                    signal_room_count, prior_rooms + (0 if current_seen else 1)
                )

        actor_join = ""
        actor_clause: str
        actor_parameters: tuple[object, ...]
        if did is not None:
            actor_clause = "e.did = ?"
            actor_parameters = (did,)
        else:
            actor_join = " JOIN event_identity_metadata actor ON actor.event_id = e.id"
            actor_clause = "e.did IS NULL AND actor.normalized_sender_name = ?"
            actor_parameters = (normalized_name,)
        activity_count = 1 + int(
            connection.execute(
                "SELECT count(*) FROM events e"
                + actor_join
                + " WHERE "
                + actor_clause
                + " AND "
                + prior_identity,
                (*actor_parameters, minute_cutoff.isoformat(), *prior_params),
            ).fetchone()[0]
        )
        bucket_counts = [
            int(row[0])
            for row in connection.execute(
                """SELECT count(*) FROM events e"""
                + actor_join
                + " WHERE "
                + actor_clause
                + " AND e.message_timestamp < ? AND "
                + prior_identity
                + " GROUP BY CAST(strftime('%s', e.message_timestamp) AS INTEGER) / 60",
                (
                    *actor_parameters,
                    baseline_end.isoformat(),
                    baseline_cutoff.isoformat(),
                    *prior_params,
                ),
            )
        ]
        median = float(statistics.median(bucket_counts)) if bucket_counts else 0.0
        deviations = [abs(value - median) for value in bucket_counts]
        mad = float(statistics.median(deviations)) if deviations else 0.0
        burst_threshold = max(
            BURST_FLOOR_PER_MINUTE, math.ceil(median + 6 * max(mad, 1.0))
        )

        coverage = connection.execute(
            """SELECT count(DISTINCT sequence), min(sequence), max(sequence)
            FROM events e WHERE e.room = ? AND """
            + prior_identity,
            (room, signal_cutoff.isoformat(), *prior_params),
        ).fetchone()
        observed_sequences = 1 + int(coverage[0])
        minimum_sequence = min(sequence, int(coverage[1])) if coverage[1] is not None else sequence
        maximum_sequence = max(sequence, int(coverage[2])) if coverage[2] is not None else sequence
        sequence_span = maximum_sequence - minimum_sequence + 1
        coverage_ratio = min(1.0, observed_sequences / sequence_span)
        coverage_sufficient = observed_sequences >= 10 and coverage_ratio >= 0.9
        qualified_burst = (
            activity_count >= burst_threshold and coverage_sufficient
        )

        return HistoricalContext(
            did_name_inconsistent=len(did_names) > 1,
            name_did_inconsistent=len(name_dids) > 1,
            did_recent_name_count=min(len(did_names), 10_000),
            name_recent_did_count=min(len(name_dids), 10_000),
            repeated_equivalent_signal_count=min(repeated_count, 10_000),
            activity_count_1m=min(activity_count, 10_000),
            activity_baseline_median=round(median, 3),
            activity_baseline_mad=round(mad, 3),
            activity_burst_threshold=min(burst_threshold, 10_000),
            collector_coverage_ratio=round(coverage_ratio, 4),
            collector_coverage_sufficient=coverage_sufficient,
            qualified_activity_burst=qualified_burst,
            signal_room_count=min(signal_room_count, 10_000),
        )

    @staticmethod
    def _persist_shadow_evaluation(
        connection: sqlite3.Connection,
        *,
        event_id: int,
        evaluation: RiskEvaluation,
    ) -> None:
        connection.execute(
            """INSERT OR REPLACE INTO risk_evaluations (
                event_id, engine_version, score, shadow_classification,
                evaluated_at, context_json, risk_families_json,
                temporal_corroboration, gate_explanation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                evaluation.engine_version,
                evaluation.score,
                evaluation.classification.value,
                datetime.now(UTC).isoformat(),
                json.dumps(evaluation.context.as_bounded_dict(), sort_keys=True),
                json.dumps(evaluation.risk_families),
                int(evaluation.temporal_corroboration),
                evaluation.gate_explanation,
            ),
        )
        connection.execute(
            "DELETE FROM event_signals WHERE event_id = ? AND engine_version = ?",
            (event_id, evaluation.engine_version),
        )
        connection.executemany(
            """INSERT INTO event_signals (
                event_id, engine_version, code, points, family, kind
            ) VALUES (?, ?, ?, ?, ?, ?)""",
            (
                (
                    event_id,
                    evaluation.engine_version,
                    contribution.code,
                    contribution.points,
                    contribution.family,
                    contribution.kind,
                )
                for contribution in evaluation.contributions
            ),
        )

    def backfill_shadow_risk(
        self, engine: RiskEngine | None = None, *, batch_size: int = 250
    ) -> int:
        """Evaluate missing risk-v2 rows chronologically; safe to run repeatedly."""

        if not 1 <= batch_size <= 10_000:
            raise ValueError("batch_size must be between 1 and 10000")
        selected_engine = engine or RiskEngine()
        inserted = 0
        with sqlite3.connect(self.path, timeout=30) as connection:
            connection.row_factory = sqlite3.Row
            events = connection.execute(
                """SELECT e.id, e.message_timestamp, e.room,
                    e.sequence, e.sender_name, e.did, e.did_present,
                    e.signed_identity_present, e.flags_json
                FROM events e
                WHERE NOT EXISTS (
                    SELECT 1 FROM risk_evaluations r
                    WHERE r.event_id = e.id AND r.engine_version = ?
                )
                ORDER BY e.message_timestamp, e.id""",
                (selected_engine.version,),
            ).fetchall()
            for row in events:
                flags = set(json.loads(row["flags_json"]))
                self._evaluate_shadow_event(
                    connection,
                    event_id=int(row["id"]),
                    message_timestamp=str(row["message_timestamp"]),
                    room=str(row["room"]),
                    sequence=int(row["sequence"]),
                    sender_name=str(row["sender_name"]),
                    did=str(row["did"]) if row["did"] is not None else None,
                    did_present=bool(row["did_present"]),
                    signed_identity_present=bool(row["signed_identity_present"]),
                    write_capable_route=(
                        SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL.value in flags
                    ),
                    engine=selected_engine,
                )
                inserted += 1
                if inserted % batch_size == 0:
                    connection.commit()
        return inserted

    def shadow_risk_report(
        self,
        hours: int = 24,
        *,
        generated_at: datetime | None = None,
        engine_version: str = ENGINE_VERSION,
    ) -> dict[str, object]:
        """Return internal metadata-only calibration totals for one engine version."""

        if isinstance(hours, bool) or not isinstance(hours, int) or hours <= 0:
            raise ValueError("hours must be a positive integer")
        selected_time = generated_at or datetime.now(UTC)
        if selected_time.tzinfo is None or selected_time.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        selected_time = selected_time.astimezone(UTC)
        cutoff = selected_time - timedelta(hours=hours)
        bounds = (cutoff.isoformat(), selected_time.isoformat(), engine_version)
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute(
                """SELECT r.shadow_classification, count(*)
                FROM risk_evaluations r JOIN events e ON e.id = r.event_id
                WHERE e.observed_at >= ? AND e.observed_at <= ?
                  AND r.engine_version = ?
                GROUP BY r.shadow_classification""",
                bounds,
            ).fetchall()
            evaluated = sum(int(row[1]) for row in rows)
            observed = int(
                connection.execute(
                    "SELECT count(*) FROM events WHERE observed_at >= ? AND observed_at <= ?",
                    bounds[:2],
                ).fetchone()[0]
            )
            signals = connection.execute(
                """SELECT s.code, count(*) AS events, sum(s.points) AS points
                FROM event_signals s JOIN events e ON e.id = s.event_id
                WHERE e.observed_at >= ? AND e.observed_at <= ?
                  AND s.engine_version = ? AND s.points > 0
                GROUP BY s.code ORDER BY events DESC, s.code LIMIT 10""",
                bounds,
            ).fetchall()
        counts = {str(row[0]).casefold(): int(row[1]) for row in rows}
        return {
            "engine_version": engine_version,
            "mode": "shadow",
            "period_hours": hours,
            "generated_at": selected_time.isoformat().replace("+00:00", "Z"),
            "evaluated": evaluated,
            "unevaluated": max(0, observed - evaluated),
            "classification": {
                name: counts.get(name, 0)
                for name in ("critical", "high", "medium", "low", "info", "none")
            },
            "top_contributing_signals": [
                {"code": str(row[0]), "events": int(row[1]), "points": int(row[2])}
                for row in signals
            ],
        }

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
