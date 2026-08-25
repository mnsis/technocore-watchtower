import asyncio
import socket

from app.adapter import adapt_room_response
from app.runtime import PollingWorker, RuntimeState
from app.storage import EventStore
from app.transport import TransportResult
from app.watcher import Watcher


def live_shape_record(**overrides):
    record = {
        "seq": 9,
        "ts": "2026-01-02T03:04:05Z",
        "from": "alice",
        "text": "hello",
        "nonce": 123,
    }
    record.update(overrides)
    return record


def test_adapter_maps_only_observed_unambiguous_fields():
    records = list(adapt_room_response(
        {"room": "lobby", "messages": [live_shape_record()]}, "lobby"
    ))
    assert records == [{
        "room": "lobby",
        "sequence": 9,
        "timestamp": "2026-01-02T03:04:05Z",
        "sender_name": "alice",
        "did": None,
        "signed_identity_present": False,
        "text": "hello",
    }]


def test_adapter_ignores_unknown_identity_like_fields():
    records = list(adapt_room_response(
        {"room": "lobby", "messages": [live_shape_record(
            did="did:key:zUnclear", verified=True, signature="unclear", extra={"x": 1}
        )]},
        "lobby",
    ))
    assert records[0]["did"] is None
    assert records[0]["signed_identity_present"] is False
    assert set(records[0]) == {
        "room", "sequence", "timestamp", "sender_name", "did",
        "signed_identity_present", "text",
    }


def test_adapter_maps_documented_server_signed_did_metadata():
    did = "did:key:z6Mk" + "1" * 44
    records = list(
        adapt_room_response(
            {
                "room": "lobby",
                "messages": [live_shape_record(**{"from": did, "nonce": 123})],
            },
            "lobby",
        )
    )
    assert records[0]["sender_name"] == did
    assert records[0]["did"] == did
    assert records[0]["signed_identity_present"] is True


def test_did_shaped_sender_without_signed_nonce_is_not_mapped_as_signed():
    did = "did:key:z6Mk" + "1" * 44
    record = live_shape_record(**{"from": did})
    record.pop("nonce")
    records = list(adapt_room_response({"room": "lobby", "messages": [record]}, "lobby"))
    assert records[0]["did"] is None
    assert records[0]["signed_identity_present"] is False


def test_malformed_live_records_are_skipped_without_crashing():
    payload = {
        "room": "lobby",
        "messages": [None, "bad", {}, live_shape_record(seq=True), live_shape_record(text=None)],
    }
    assert list(adapt_room_response(payload, "lobby")) == []
    assert list(adapt_room_response({"room": "other", "messages": []}, "lobby")) == []


def test_runtime_state_records_success_and_failure():
    state = RuntimeState(("lobby",))
    state.record_attempt()
    state.record_failure("rate_limited")
    failed = state.snapshot()
    assert failed["last_poll_attempt"] is not None
    assert failed["last_transport_error"] == "rate_limited"
    assert failed["total_transport_failures"] == 1
    state.record_success()
    state.clear_error()
    successful = state.snapshot()
    assert successful["last_successful_poll"] is not None
    assert successful["last_transport_error"] is None


class FakeTransport:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def read_room(self, room, **kwargs):
        self.calls.append((room, kwargs))
        return self.result


def test_poll_worker_uses_allowlist_and_never_fetches_message_url(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("message-derived network request attempted")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    payload = {
        "room": "lobby",
        "messages": [live_shape_record(text="https://evil.invalid/payload")],
    }
    transport = FakeTransport(TransportResult(True, 200, data=payload))
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    state = RuntimeState(("lobby",))
    worker = PollingWorker(transport, Watcher(store), state, poll_interval=5)
    assert asyncio.run(worker.poll_once()) is True
    assert [call[0] for call in transport.calls] == ["lobby"]
    assert transport.calls[0][1] == {"since": 0, "wait": 2, "limit": 5}
    assert store.dashboard_summary()["total"] == 1


def test_poll_worker_handles_transport_failure_without_retry_loop(tmp_path):
    transport = FakeTransport(
        TransportResult(False, 429, error="rate_limited", retry_after_seconds=30)
    )
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    state = RuntimeState(("lobby",))
    worker = PollingWorker(transport, Watcher(store), state, poll_interval=5)
    assert asyncio.run(worker.poll_once()) is False
    assert len(transport.calls) == 1
    assert state.snapshot()["total_transport_failures"] == 1
    assert worker._retry_after_hint == 30
