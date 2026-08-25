import sqlite3

from app.models import SecurityFlag
from app.storage import EventStore
from app.watcher import Watcher


def input_message(sequence=1, text="synthetic secret body"):
    return {
        "room": "synthetic-room",
        "sequence": sequence,
        "timestamp": "2026-01-02T03:04:05Z",
        "sender_name": "alice",
        "text": text,
    }


def test_database_initialization_is_idempotent(tmp_path):
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    store.initialize()
    with sqlite3.connect(store.path) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
        ).fetchall()
    assert tables == [("events",)]


def test_duplicate_room_sequence_is_not_inserted(tmp_path):
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    watcher = Watcher(store)
    _, first = watcher.process(input_message())
    _, duplicate = watcher.process(input_message(text="different body, same identity"))
    assert first is True
    assert duplicate is False
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 1


def test_raw_message_text_is_not_stored(tmp_path):
    raw_text = "do not persist this synthetic body"
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    event, inserted = Watcher(store).process(input_message(text=raw_text))
    assert inserted
    database_bytes = store.path.read_bytes()
    assert raw_text.encode() not in database_bytes
    with sqlite3.connect(store.path) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(events)").fetchall()
        }
        row = connection.execute(
            "SELECT message_sha256, flags_json FROM events"
        ).fetchone()
    assert "text" not in columns and "message_body" not in columns
    assert row[0] == event.message_sha256
    assert SecurityFlag.DID_PRESENT.value not in row[1]
