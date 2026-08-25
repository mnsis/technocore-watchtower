import sqlite3

from fastapi.testclient import TestClient

from app.dashboard import PROJECT_ROOT, DashboardSettings, create_app
from app.parser import parse_message
from app.scanner import scan_message

RAW_TEXT = "synthetic raw body must remain unavailable"
MALICIOUS_SENDER = '<script>alert("x")</script>'


def make_client(tmp_path):
    settings = DashboardSettings(
        database_path=tmp_path / "events.sqlite3",
        monitored_rooms=("lobby",),
        polling_enabled=False,
    )
    app = create_app(settings)
    event = scan_message(
        parse_message({
            "room": "lobby",
            "sequence": 7,
            "timestamp": "2026-01-02T03:04:05Z",
            "sender_name": MALICIOUS_SENDER,
            "did": "did:key:zSynthetic",
            "signed_identity_present": False,
            "text": RAW_TEXT,
        })
    )
    app.state.store.insert(event)
    return TestClient(app), settings


def test_dashboard_root_and_events_load(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        root = client.get("/")
        events = client.get("/events")
    assert root.status_code == 200 and "Technocore Watchtower" in root.text
    assert events.status_code == 200 and "Security events" in events.text


def test_dashboard_rooms_and_local_chart_assets_load(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        root = client.get("/")
        rooms = client.get("/rooms")
        script = client.get("/static/app.js")
        live_script = client.get("/static/live.js")
    assert rooms.status_code == 200
    assert "Observed rooms" in rooms.text and "#lobby" in rooms.text
    assert 'data-chart="line"' in root.text
    assert "Observations over time" in root.text
    assert script.status_code == 200 and "renderCharts" in script.text
    assert live_script.status_code == 200
    assert 'data-live-metric="observations"' in root.text
    assert "data-live-event-container" in root.text
    assert "data-live-room-region" in root.text
    assert "Connecting…" in root.text


def test_live_script_uses_safe_read_only_non_overlapping_polling():
    script = (PROJECT_ROOT / "web" / "static" / "live.js").read_text()
    for endpoint in (
        'fetchJson("/api/v1/summary?hours=24"',
        'fetchJson("/api/v1/events?limit=20"',
        'fetchJson("/api/v1/rooms"',
    ):
        assert endpoint in script
    assert "const POLL_INTERVAL_MS = 5000" in script
    assert "const HIDDEN_INTERVAL_MS = 30000" in script
    assert "if (this.running)" in script
    assert 'document.addEventListener("visibilitychange"' in script
    assert "Promise.allSettled" in script
    assert 'method: "GET"' in script
    assert ".textContent" in script
    assert ".innerHTML" not in script


def test_event_filters_are_get_only_and_preserve_metadata_privacy(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        filtered = client.get("/events?room=lobby&severity=INFO&flag=DID_PRESENT")
        invalid = client.get("/events?room=../lobby")
    assert filtered.status_code == 200
    assert "Apply filters" in filtered.text
    assert "did:key:zSynthetic" in filtered.text
    assert RAW_TEXT not in filtered.text
    assert invalid.status_code == 422


def test_event_metadata_renders_without_raw_message(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        response = client.get("/events/1")
    assert response.status_code == 200
    assert "did:key:zSynthetic" in response.text
    assert "DID PRESENT" in response.text
    assert RAW_TEXT not in response.text
    assert "SHA-256" in response.text


def test_malicious_sender_is_html_escaped(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        response = client.get("/events")
    assert MALICIOUS_SENDER not in response.text
    assert "&lt;script&gt;" in response.text


def test_security_headers_are_present(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        response = client.get("/")
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "form-action 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-frame-options"] == "DENY"


def test_dashboard_has_no_write_controls_or_write_methods(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        page = client.get("/").text.casefold()
        post = client.post("/events")
    for control in ("send message", "reply", "moderate", "delete", "block user", "report user"):
        assert control not in page
    assert "<form" not in page
    assert post.status_code == 405


def test_raw_message_is_neither_retrievable_nor_in_database(tmp_path):
    client, settings = make_client(tmp_path)
    with client:
        assert client.get("/messages/7").status_code == 404
        assert RAW_TEXT not in client.get("/").text
    assert RAW_TEXT.encode() not in settings.database_path.read_bytes()
    with sqlite3.connect(settings.database_path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
    assert "text" not in columns and "message_body" not in columns


def test_health_is_read_only_and_does_not_fabricate_poll_time(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        response = client.get("/health")
    assert response.json()["mode"] == "read-only"
    assert response.json()["last_successful_poll"] is None


def test_phase_3b_settings_enforce_loopback_and_room_allowlist(tmp_path):
    DashboardSettings(host="127.0.0.1", port=8787, database_path=tmp_path / "ok.db")
    for kwargs in (
        {"host": "0.0.0.0"},
        {"host": "::"},
        {"monitored_rooms": ("lobby", "../other")},
        {"monitored_rooms": ()},
    ):
        try:
            DashboardSettings(database_path=tmp_path / "bad.db", **kwargs)
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe settings accepted: {kwargs}")
