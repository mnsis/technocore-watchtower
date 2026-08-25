import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from app.risk import (
    ENGINE_VERSION,
    NORMALIZATION_VERSION,
    EventEvidence,
    HistoricalContext,
    ProtectedNameMatch,
    RiskEngine,
    ShadowClassification,
    normalize_sender_name,
    protected_name_match,
)
from app.storage import EventStore
from app.watcher import Watcher

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
WRITE_URL = "https://technocore.chat/r/lobby/say/alice/hello"


def evidence(
    *,
    did=False,
    signed=False,
    match=ProtectedNameMatch.NONE,
    write=False,
):
    return EventEvidence(
        did_present=did,
        signed_identity_present=signed,
        protected_name_match=match,
        write_capable_route=write,
    )


def contribution_points(result):
    return {item.code: item.points for item in result.contributions}


@pytest.mark.parametrize(
    ("selected", "expected"),
    [
        (evidence(), (0, ShadowClassification.NONE, {})),
        (
            evidence(did=True, signed=True),
            (0, ShadowClassification.INFO, {"DID_PRESENT": 0}),
        ),
        (
            evidence(match=ProtectedNameMatch.EXACT),
            (25, ShadowClassification.LOW, {"UNSIGNED_PROTECTED_NAME_EXACT": 25}),
        ),
        (
            evidence(match=ProtectedNameMatch.CONFUSABLE),
            (
                15,
                ShadowClassification.LOW,
                {"UNSIGNED_PROTECTED_NAME_CONFUSABLE": 15},
            ),
        ),
        (
            evidence(write=True),
            (35, ShadowClassification.MEDIUM, {"WRITE_CAPABLE_ROUTE": 35}),
        ),
        (
            evidence(match=ProtectedNameMatch.EXACT, write=True),
            (
                75,
                ShadowClassification.HIGH,
                {
                    "UNSIGNED_PROTECTED_NAME_EXACT": 25,
                    "WRITE_CAPABLE_ROUTE": 35,
                    "IDENTITY_CAPABILITY_CORRELATION": 15,
                },
            ),
        ),
    ],
)
def test_synthetic_base_severity_calibration(selected, expected):
    result = RiskEngine().evaluate(selected)
    score, classification, contributions = expected
    assert result.score == score
    assert result.classification is classification
    assert contribution_points(result) == contributions


def test_correlated_repeated_and_propagating_pattern_reaches_critical():
    context = HistoricalContext(
        repeated_equivalent_signal_count=2,
        signal_room_count=2,
    )
    result = RiskEngine().evaluate(
        evidence(match=ProtectedNameMatch.EXACT, write=True), context
    )
    assert result.score == 90
    assert result.classification is ShadowClassification.CRITICAL
    assert result.temporal_corroboration
    assert contribution_points(result) == {
        "UNSIGNED_PROTECTED_NAME_EXACT": 25,
        "WRITE_CAPABLE_ROUTE": 35,
        "IDENTITY_CAPABILITY_CORRELATION": 15,
        "REPEATED_RISK_SIGNAL": 10,
        "CROSS_ROOM_SIGNAL_PROPAGATION": 5,
    }


@pytest.mark.parametrize(
    "context",
    [
        HistoricalContext(
            activity_count_1m=100,
            collector_coverage_sufficient=True,
            qualified_activity_burst=True,
        ),
        HistoricalContext(signal_room_count=3),
        HistoricalContext(did_name_inconsistent=True, did_recent_name_count=2),
        HistoricalContext(repeated_equivalent_signal_count=50),
    ],
)
def test_benign_context_cannot_escalate_informational_did(context):
    result = RiskEngine().evaluate(evidence(did=True, signed=True), context)
    assert result.score == 0
    assert result.classification is ShadowClassification.INFO
    assert contribution_points(result) == {"DID_PRESENT": 0}


def test_generic_unsigned_and_repeated_content_metadata_do_not_escalate():
    context = HistoricalContext(
        repeated_equivalent_signal_count=500,
        activity_count_1m=100,
        qualified_activity_burst=True,
        signal_room_count=4,
    )
    result = RiskEngine().evaluate(evidence(), context)
    assert result.score == 0
    assert result.classification is ShadowClassification.NONE
    assert result.contributions == ()


def test_context_cap_and_single_family_gate_prevent_high():
    context = HistoricalContext(
        did_name_inconsistent=True,
        repeated_equivalent_signal_count=2,
        activity_count_1m=100,
        qualified_activity_burst=True,
        signal_room_count=3,
    )
    result = RiskEngine().evaluate(evidence(write=True), context)
    assert result.score == 55
    assert result.classification is ShadowClassification.MEDIUM
    assert sum(item.points for item in result.contributions if item.kind == "modifier") == 20


@pytest.mark.parametrize(
    ("name", "normalized", "match"),
    [
        (" Flop--Labs ", "flop_labs", ProtectedNameMatch.EXACT),
        ("floplabs", "floplabs", ProtectedNameMatch.CONFUSABLE),
        ("supp0rt", "supp0rt", ProtectedNameMatch.CONFUSABLE),
        ("officialx", "officialx", ProtectedNameMatch.CONFUSABLE),
        ("admln", "admln", ProtectedNameMatch.NONE),
        ("suppоrt", "suppоrt", ProtectedNameMatch.NONE),  # Cyrillic o is not folded.
    ],
)
def test_name_normalization_and_bounded_matching(name, normalized, match):
    assert normalize_sender_name(name) == normalized
    assert protected_name_match(name) is match


def test_fuzzy_boundary_signed_protected_name_and_high_gate_edges():
    engine = RiskEngine()
    assert protected_name_match("officialx") is ProtectedNameMatch.CONFUSABLE
    assert protected_name_match("officxxl") is ProtectedNameMatch.NONE
    signed = engine.event_evidence(
        sender_name="admin",
        did_present=True,
        signed_identity_present=True,
        write_capable_route=False,
    )
    assert signed.protected_name_match is ProtectedNameMatch.NONE
    assert engine.evaluate(signed).classification is ShadowClassification.INFO
    classification, explanation = engine._classify(
        score=85, informational=False, family_count=1, temporal_corroboration=True
    )
    assert classification is ShadowClassification.MEDIUM
    assert explanation == "HIGH requires at least two independent risk families."
    classification, explanation = engine._classify(
        score=85, informational=False, family_count=2, temporal_corroboration=False
    )
    assert classification is ShadowClassification.HIGH
    assert explanation == "CRITICAL requires recent temporal corroboration."
    critical = engine.evaluate(
        evidence(match=ProtectedNameMatch.EXACT, write=True),
        HistoricalContext(repeated_equivalent_signal_count=2),
    )
    assert critical.score == 85
    assert critical.classification is ShadowClassification.CRITICAL


def message(sequence, *, sender="alice", text="hello", room="lobby", minute=0, did=None):
    return {
        "room": room,
        "sequence": sequence,
        "timestamp": (NOW + timedelta(minutes=minute)).isoformat(),
        "sender_name": sender,
        "did": did,
        "signed_identity_present": did is not None,
        "text": text,
    }


def test_shadow_storage_is_separate_private_and_preserves_authoritative_severity(tmp_path):
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    event, inserted = Watcher(store).process(
        message(1, sender="admin", text=f"review {WRITE_URL}")
    )
    assert inserted and event.severity.name == "HIGH"
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            """SELECT e.severity, r.score, r.shadow_classification,
                im.normalized_sender_name, im.normalization_version, r.context_json
            FROM events e JOIN risk_evaluations r ON r.event_id = e.id
            JOIN event_identity_metadata im ON im.event_id = e.id"""
        ).fetchone()
        signals = dict(
            connection.execute("SELECT code, points FROM event_signals").fetchall()
        )
        schema = " ".join(
            item[0]
            for item in connection.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
            )
        ).casefold()
    assert row[:5] == ("HIGH", 75, "HIGH", "admin", NORMALIZATION_VERSION)
    assert json.loads(row[5])["repeated_equivalent_signal_count"] == 0
    assert signals["WRITE_CAPABLE_ROUTE"] == 35
    public_event = store.api_events(limit=1)[0][0]
    assert public_event["severity"] == "HIGH"
    assert "score" not in public_event and "shadow_classification" not in public_event
    assert WRITE_URL not in store.path.read_bytes().decode("utf-8", errors="ignore")
    assert "message_body" not in schema and "raw_message" not in schema
    assert "reputation" not in schema and "profile" not in schema


def test_repetition_is_bounded_context_and_third_correlated_event_is_critical(tmp_path):
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    watcher = Watcher(store)
    for sequence in range(1, 4):
        watcher.process(
            message(sequence, sender="admin", text=WRITE_URL, minute=sequence)
        )
    with sqlite3.connect(store.path) as connection:
        rows = connection.execute(
            """SELECT score, shadow_classification FROM risk_evaluations
            ORDER BY event_id"""
        ).fetchall()
    assert rows == [(75, "HIGH"), (75, "HIGH"), (85, "CRITICAL")]


def test_identity_mapping_context_is_recent_and_does_not_escalate_by_itself(tmp_path):
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    watcher = Watcher(store)
    did_a = "did:key:zIdentityA"
    did_b = "did:key:zIdentityB"
    watcher.process(message(1, sender="alice", did=did_a))
    watcher.process(message(2, sender="alice-renamed", did=did_a, minute=1))
    watcher.process(message(3, sender="alice-renamed", did=did_b, minute=2))
    with sqlite3.connect(store.path) as connection:
        rows = connection.execute(
            "SELECT score, shadow_classification, context_json FROM risk_evaluations ORDER BY event_id"
        ).fetchall()
    second = json.loads(rows[1][2])
    third = json.loads(rows[2][2])
    assert rows[1][:2] == (0, "INFO")
    assert second["did_name_inconsistent"] is True
    assert second["did_recent_name_count"] == 2
    assert rows[2][:2] == (0, "INFO")
    assert third["name_did_inconsistent"] is True
    assert third["name_recent_did_count"] == 2


def test_signal_propagation_and_qualified_burst_use_bounded_source_time_context(tmp_path):
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    watcher = Watcher(store)
    watcher.process(message(1, sender="admin", room="lobby"))
    watcher.process(message(1, sender="admin", room="technocore", minute=1))
    for sequence in range(2, 11):
        data = message(sequence, sender="admin", room="lobby")
        data["timestamp"] = (NOW + timedelta(seconds=sequence)).isoformat()
        watcher.process(data)
    with sqlite3.connect(store.path) as connection:
        propagation = connection.execute(
            "SELECT score, context_json FROM risk_evaluations WHERE event_id = 2"
        ).fetchone()
        burst = connection.execute(
            "SELECT context_json FROM risk_evaluations ORDER BY event_id DESC LIMIT 1"
        ).fetchone()[0]
    propagation_context = json.loads(propagation[1])
    burst_context = json.loads(burst)
    assert propagation[0] == 30
    assert propagation_context["signal_room_count"] == 2
    assert burst_context["activity_count_1m"] == 10
    assert burst_context["activity_burst_threshold"] == 10
    assert burst_context["collector_coverage_sufficient"] is True
    assert burst_context["qualified_activity_burst"] is True


def test_burst_threshold_boundary_with_and_without_base_evidence(tmp_path):
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    watcher = Watcher(store)
    for sequence in range(1, 10):
        data = message(sequence, sender="admin")
        data["timestamp"] = (NOW + timedelta(seconds=sequence)).isoformat()
        watcher.process(data)
    with sqlite3.connect(store.path) as connection:
        near_context = json.loads(
            connection.execute(
                "SELECT context_json FROM risk_evaluations ORDER BY event_id DESC LIMIT 1"
            ).fetchone()[0]
        )
    assert near_context["activity_count_1m"] == 9
    assert near_context["qualified_activity_burst"] is False

    no_base = RiskEngine().evaluate(
        evidence(),
        HistoricalContext(
            activity_count_1m=10,
            activity_burst_threshold=10,
            collector_coverage_sufficient=True,
            qualified_activity_burst=True,
        ),
    )
    assert no_base.score == 0
    assert no_base.classification is ShadowClassification.NONE


def test_quoted_and_repeated_write_routes_remain_ambiguous_medium(tmp_path):
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    watcher = Watcher(store)
    for sequence in range(1, 4):
        event, inserted = watcher.process(
            message(
                sequence,
                text=f"Documentation example only: `{WRITE_URL}`",
                minute=sequence,
            )
        )
        assert inserted and event.severity.name == "MEDIUM"
    with sqlite3.connect(store.path) as connection:
        rows = connection.execute(
            "SELECT score, shadow_classification FROM risk_evaluations ORDER BY event_id"
        ).fetchall()
    assert rows == [(35, "MEDIUM"), (35, "MEDIUM"), (45, "MEDIUM")]


def test_private_diagnostics_compare_without_exposing_identity_or_content(tmp_path):
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    watcher = Watcher(store)
    watcher.process(message(1))
    watcher.process(message(2, sender="did:key:zInfo", did="did:key:zInfo"))
    watcher.process(message(3, sender="supp0rt"))
    watcher.process(message(4, sender="admin"))
    watcher.process(message(5, text=f"benign quotation {WRITE_URL}"))
    diagnostics = store.risk_v2_diagnostics(
        24, generated_at=datetime.now(UTC) + timedelta(hours=1)
    )
    assert diagnostics["production_distribution"] == {
        "HIGH": 0,
        "MEDIUM": 1,
        "LOW": 1,
        "INFO": 1,
        "NONE": 2,
    }
    assert diagnostics["shadow_distribution"] == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 1,
        "LOW": 2,
        "INFO": 1,
        "NONE": 1,
    }
    assert diagnostics["disagreements"] == 1
    assert {
        (item["production"], item["shadow"], item["events"])
        for item in diagnostics["disagreement_matrix"]
    } == {
        ("INFO", "INFO", 1),
        ("LOW", "LOW", 1),
        ("MEDIUM", "MEDIUM", 1),
        ("NONE", "LOW", 1),
        ("NONE", "NONE", 1),
    }
    encoded = json.dumps(diagnostics)
    assert "did:key:zInfo" not in encoded
    assert WRITE_URL not in encoded
    assert "benign quotation" not in encoded


def create_legacy_database(path):
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """CREATE TABLE events (
                id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL,
                message_timestamp TEXT NOT NULL, room TEXT NOT NULL,
                sequence INTEGER NOT NULL, sender_name TEXT NOT NULL, did TEXT,
                did_present INTEGER NOT NULL, signed_identity_present INTEGER NOT NULL,
                flags_json TEXT NOT NULL, severity TEXT NOT NULL,
                message_sha256 TEXT NOT NULL, UNIQUE(room, sequence)
            );"""
        )
        for sequence, (sender, did, flags, severity) in enumerate(
            (
                ("alice", None, [], "NONE"),
                ("did:key:zSynthetic", "did:key:zSynthetic", ["DID_PRESENT"], "INFO"),
            ),
            1,
        ):
            connection.execute(
                """INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sequence,
                    NOW.isoformat(),
                    (NOW + timedelta(minutes=sequence)).isoformat(),
                    "lobby",
                    sequence,
                    sender,
                    did,
                    int(did is not None),
                    int(did is not None),
                    json.dumps(flags),
                    severity,
                    f"{sequence:064x}",
                ),
            )


def test_legacy_migration_and_backfill_are_idempotent(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    create_legacy_database(path)
    store = EventStore(path)
    store.initialize()
    store.initialize()
    assert store.backfill_shadow_risk() == 2
    assert store.backfill_shadow_risk() == 0
    report = store.shadow_risk_report(24, generated_at=NOW + timedelta(hours=1))
    assert report["classification"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 1,
        "none": 1,
    }
    assert report["unevaluated"] == 0


def test_concurrent_ingestion_keeps_shadow_rows_one_to_one(tmp_path):
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()

    def insert(sequence):
        return Watcher(store).process(message(sequence))[1]

    with ThreadPoolExecutor(max_workers=4) as executor:
        assert all(executor.map(insert, range(1, 21)))
    with sqlite3.connect(store.path) as connection:
        events = connection.execute("SELECT count(*) FROM events").fetchone()[0]
        evaluations = connection.execute(
            "SELECT count(*) FROM risk_evaluations WHERE engine_version = ?",
            (ENGINE_VERSION,),
        ).fetchone()[0]
    assert events == evaluations == 20
