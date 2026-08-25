import json
import sqlite3
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.dashboard import DashboardSettings, create_app
from app.watcher import Watcher

NOW = datetime.now(UTC)


def create_test_client(tmp_path):
    settings = DashboardSettings(
        database_path=tmp_path / "events.sqlite3",
        monitored_rooms=("lobby", "technocore"),
        polling_enabled=False,
    )
    app = create_app(settings)
    rows = (
        (NOW - timedelta(hours=30), "lobby", 1, "alice", None, 0, "NONE", []),
        (
            NOW - timedelta(hours=2),
            "lobby",
            2,
            "support",
            None,
            0,
            "HIGH",
            [
                "UNSIGNED_PRIVILEGED_NAME",
                "POTENTIAL_TECHNOCORE_WRITE_URL",
                "SUSPICIOUS_COMBINATION",
            ],
        ),
        (
            NOW - timedelta(hours=1),
            "technocore",
            3,
            "did:key:z6Mk" + "1" * 44,
            "did:key:z6Mk" + "1" * 44,
            1,
            "INFO",
            ["DID_PRESENT"],
        ),
        (
            NOW - timedelta(minutes=30),
            "technocore",
            4,
            "bob",
            None,
            0,
            "MEDIUM",
            ["POTENTIAL_TECHNOCORE_WRITE_URL"],
        ),
    )
    with sqlite3.connect(settings.database_path) as connection:
        for observed, room, sequence, sender, did, signed, severity, flags in rows:
            connection.execute(
                """INSERT INTO events (
                    observed_at, message_timestamp, room, sequence, sender_name,
                    did, did_present, signed_identity_present, flags_json,
                    severity, message_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    observed.isoformat(),
                    observed.isoformat(),
                    room,
                    sequence,
                    sender,
                    did,
                    signed,
                    signed,
                    json.dumps(flags),
                    severity,
                    f"{sequence:064x}",
                ),
            )
    return TestClient(app), app


def test_summary_endpoint_and_hours_filter(tmp_path):
    client, _ = create_test_client(tmp_path)
    with client:
        daily = client.get("/api/v1/summary")
        extended = client.get("/api/v1/summary?hours=48")
    assert daily.status_code == 200
    assert daily.json()["api_version"] == "v1"
    assert daily.json()["period_hours"] == 24
    assert daily.json()["observations"] == 3
    assert daily.json()["identity"]["did_present"] == 1
    assert daily.json()["monitored_rooms"] == ["lobby", "technocore"]
    assert extended.json()["observations"] == 4


def test_events_cursor_pagination(tmp_path):
    client, _ = create_test_client(tmp_path)
    with client:
        first = client.get("/api/v1/events?limit=2").json()
        cursor = first["pagination"]["next_before_id"]
        second = client.get(f"/api/v1/events?limit=2&before_id={cursor}").json()
    assert [event["id"] for event in first["events"]] == [4, 3]
    assert cursor == 3
    assert [event["id"] for event in second["events"]] == [2, 1]
    assert second["pagination"]["next_before_id"] is None


def test_events_room_severity_and_flag_filters(tmp_path):
    client, _ = create_test_client(tmp_path)
    with client:
        room = client.get("/api/v1/events?room=lobby").json()
        severity = client.get("/api/v1/events?severity=high").json()
        flag = client.get(
            "/api/v1/events?flag=POTENTIAL_TECHNOCORE_WRITE_URL"
        ).json()
    assert [event["room"] for event in room["events"]] == ["lobby", "lobby"]
    assert [event["id"] for event in severity["events"]] == [2]
    assert [event["id"] for event in flag["events"]] == [4, 2]


def test_rooms_and_single_room_summary(tmp_path):
    client, _ = create_test_client(tmp_path)
    with client:
        rooms = client.get("/api/v1/rooms").json()
        room = client.get("/api/v1/rooms/technocore").json()
    assert rooms["api_version"] == "v1"
    assert [item["room"] for item in rooms["rooms"]] == ["lobby", "technocore"]
    assert room["room"]["observations"] == 2
    assert room["room"]["flagged_events"] == 1
    assert room["room"]["severity"]["medium"] == 1


def test_invalid_room_hours_and_limit_are_rejected(tmp_path):
    client, _ = create_test_client(tmp_path)
    with client:
        assert client.get("/api/v1/rooms/INVALID").status_code == 422
        assert client.get("/api/v1/events?room=../lobby").status_code == 422
        assert client.get("/api/v1/summary?hours=0").status_code == 422
        assert client.get("/api/v1/summary?hours=8761").status_code == 422
        assert client.get("/api/v1/events?limit=201").status_code == 422


def test_valid_but_unobserved_room_returns_not_found(tmp_path):
    client, _ = create_test_client(tmp_path)
    with client:
        response = client.get("/api/v1/rooms/unobserved")
    assert response.status_code == 404


def test_api_never_returns_raw_text_or_message_urls(tmp_path):
    client, app = create_test_client(tmp_path)
    raw_text = "private synthetic body https://message-derived.invalid/secret"
    Watcher(app.state.store).process(
        {
            "room": "lobby",
            "sequence": 99,
            "timestamp": NOW.isoformat(),
            "sender_name": "alice",
            "text": raw_text,
        }
    )
    with client:
        events = client.get("/api/v1/events").text
        summary = client.get("/api/v1/summary").text
    assert raw_text not in events and raw_text not in summary
    assert "message-derived.invalid" not in events and "message-derived.invalid" not in summary
    assert '"text"' not in events and '"urls"' not in events


def test_api_is_get_only_and_has_security_headers_without_cors_wildcard(tmp_path):
    client, _ = create_test_client(tmp_path)
    with client:
        response = client.get("/api/v1/events")
        post = client.post("/api/v1/events")
        put = client.put("/api/v1/rooms/lobby")
        delete = client.delete("/api/v1/rooms/lobby")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "access-control-allow-origin" not in response.headers
    assert post.status_code == put.status_code == delete.status_code == 405
