import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from app.report import build_parser, render_human
from app.storage import EventStore
from app.watcher import Watcher

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)


def make_store(tmp_path):
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    return store


def add_event(
    store,
    *,
    sequence,
    hours_ago=1,
    room="lobby",
    signed=False,
    flags=(),
    severity="NONE",
):
    did = "did:key:z6Mk" + "1" * 44 if signed else None
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """INSERT INTO events (
                observed_at, message_timestamp, room, sequence, sender_name,
                did, did_present, signed_identity_present, flags_json,
                severity, message_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                (NOW - timedelta(hours=hours_ago)).isoformat(),
                NOW.isoformat(),
                room,
                sequence,
                did or "alice",
                did,
                int(signed),
                int(signed),
                json.dumps(list(flags)),
                severity,
                f"{sequence:064x}",
            ),
        )


def report(store, hours=24):
    return store.security_report(hours, generated_at=NOW)


def test_empty_database_report_has_clean_zero_state(tmp_path):
    result = report(make_store(tmp_path))
    assert result["observations"] == 0
    assert result["rooms_observed"] == 0
    assert result["top_flagged_rooms"] == []
    assert "No observations in the selected period." in render_human(result)


def test_report_filters_to_last_24_hours(tmp_path):
    store = make_store(tmp_path)
    add_event(store, sequence=1, hours_ago=23)
    add_event(store, sequence=2, hours_ago=25)
    assert report(store)["observations"] == 1


def test_seven_day_window_is_supported(tmp_path):
    store = make_store(tmp_path)
    add_event(store, sequence=1, hours_ago=100)
    assert report(store, 24)["observations"] == 0
    assert report(store, 168)["observations"] == 1


def test_signed_identity_metadata_count(tmp_path):
    store = make_store(tmp_path)
    add_event(store, sequence=1, signed=True, severity="INFO", flags=("DID_PRESENT",))
    assert report(store)["identity"]["signed_identity_present"] == 1


def test_unsigned_observation_count(tmp_path):
    store = make_store(tmp_path)
    add_event(store, sequence=1)
    add_event(store, sequence=2, signed=True, severity="INFO", flags=("DID_PRESENT",))
    assert report(store)["identity"]["unsigned"] == 1


def test_privileged_name_flag_count(tmp_path):
    store = make_store(tmp_path)
    add_event(
        store,
        sequence=1,
        severity="LOW",
        flags=("UNSIGNED_PRIVILEGED_NAME",),
    )
    result = report(store)
    assert result["identity"]["unsigned_privileged_name"] == 1
    assert result["flags"]["UNSIGNED_PRIVILEGED_NAME"] == 1


def test_write_url_flag_count(tmp_path):
    store = make_store(tmp_path)
    add_event(
        store,
        sequence=1,
        severity="MEDIUM",
        flags=("POTENTIAL_TECHNOCORE_WRITE_URL",),
    )
    assert report(store)["url_safety"]["potential_write_urls"] == 1


def test_all_severity_counts_are_stable(tmp_path):
    store = make_store(tmp_path)
    for sequence, severity in enumerate(("HIGH", "MEDIUM", "LOW", "INFO", "NONE"), 1):
        add_event(store, sequence=sequence, severity=severity)
    assert report(store)["severity"] == {
        "high": 1,
        "medium": 1,
        "low": 1,
        "info": 1,
        "none": 1,
    }


def test_top_flagged_rooms_count_risk_events_once(tmp_path):
    store = make_store(tmp_path)
    combined = (
        "UNSIGNED_PRIVILEGED_NAME",
        "POTENTIAL_TECHNOCORE_WRITE_URL",
        "SUSPICIOUS_COMBINATION",
    )
    add_event(store, sequence=1, room="technocore", severity="HIGH", flags=combined)
    add_event(store, sequence=2, room="technocore", severity="LOW", flags=(combined[0],))
    add_event(store, sequence=3, room="lobby", severity="MEDIUM", flags=(combined[1],))
    add_event(store, sequence=4, room="lobby", signed=True, severity="INFO", flags=("DID_PRESENT",))
    assert report(store)["top_flagged_rooms"] == [
        {"room": "technocore", "events": 2},
        {"room": "lobby", "events": 1},
    ]


def test_json_output_has_stable_schema(tmp_path):
    result = report(make_store(tmp_path))
    decoded = json.loads(json.dumps(result, sort_keys=True))
    assert set(decoded) == {
        "period_hours",
        "generated_at",
        "observations",
        "rooms_observed",
        "identity",
        "url_safety",
        "severity",
        "flags",
        "top_flagged_rooms",
    }
    assert set(decoded["identity"]) == {
        "signed_identity_present",
        "unsigned",
        "unsigned_privileged_name",
    }


def test_raw_message_content_never_appears_in_report_output(tmp_path):
    secret_body = "synthetic raw message that must not appear"
    store = make_store(tmp_path)
    Watcher(store).process(
        {
            "room": "lobby",
            "sequence": 1,
            "timestamp": NOW.isoformat(),
            "sender_name": "alice",
            "text": secret_body,
        }
    )
    result = store.security_report(24)
    assert secret_body not in render_human(result)
    assert secret_body not in json.dumps(result)


def test_optional_shadow_report_is_internal_and_metadata_only(tmp_path):
    store = make_store(tmp_path)
    Watcher(store).process(
        {
            "room": "lobby",
            "sequence": 1,
            "timestamp": NOW.isoformat(),
            "sender_name": "alice",
            "text": "private synthetic body",
        }
    )
    result = report(store)
    result["risk_v2_shadow"] = store.shadow_risk_report(24, generated_at=NOW)
    rendered = render_human(result)
    assert "risk-v2-shadow-1" in rendered
    assert "NONE:       1" in rendered
    assert "private synthetic body" not in rendered


def test_shadow_cli_flags_are_explicit():
    args = build_parser().parse_args(["--risk-shadow", "--backfill-risk-shadow"])
    assert args.risk_shadow
    assert args.backfill_risk_shadow


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "not-a-number"])
def test_invalid_hours_are_rejected(value):
    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(["--hours", value])
    assert error.value.code == 2
