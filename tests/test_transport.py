import json

import pytest

from app.storage import EventStore
from app.transport import TechnocoreTransport
from app.watcher import Watcher


class FakeResponse:
    def __init__(self, status=200, body=b"{}", headers=None):
        self.status = status
        self.reason = "synthetic"
        self._body = body
        self._headers = headers or {}

    def getheader(self, name, default=None):
        return self._headers.get(name, default)

    def read(self, amount=None):
        return self._body if amount is None else self._body[:amount]


class FakeConnection:
    def __init__(self, response):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, method, url, body=None, headers=None):
        self.requests.append((method, url, body, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def transport_with(response):
    connection = FakeConnection(response)
    calls = []

    def factory(host, port, timeout, context):
        calls.append((host, port, timeout, context))
        return connection

    return TechnocoreTransport(
        "https://example.invalid", connection_factory=factory
    ), connection, calls


@pytest.mark.parametrize(
    "room", ["", "Lobby", "../lobby", "lobby/x", "a" * 49, "lobby?wait=10"]
)
def test_invalid_room_names_are_rejected_without_connection(room):
    transport, connection, calls = transport_with(FakeResponse())
    with pytest.raises(ValueError):
        transport.read_room(room)
    assert not calls and not connection.requests


def test_room_request_uses_only_get_and_fixed_read_template():
    transport, connection, calls = transport_with(
        FakeResponse(body=json.dumps({"messages": []}).encode())
    )
    result = transport.read_room("lobby", since=10, wait=5, limit=3)
    assert result.ok
    assert calls[0][:3] == ("example.invalid", 443, 15.0)
    method, target, body, headers = connection.requests[0]
    assert method == "GET" and body is None
    assert target == "/r/lobby?format=json&since=10&wait=5&limit=3"
    assert headers["User-Agent"].startswith("technocore-watchtower/")


def test_transport_has_no_arbitrary_url_api_and_rejects_pathful_origin():
    transport, _, _ = transport_with(FakeResponse())
    assert not hasattr(transport, "fetch")
    assert not hasattr(transport, "request_url")
    with pytest.raises(ValueError):
        TechnocoreTransport("https://example.invalid/r/lobby")
    with pytest.raises(ValueError):
        TechnocoreTransport("http://example.invalid")
    with pytest.raises(ValueError):
        transport._get(  # Private defense-in-depth check against accidental misuse.
            "/r/lobby/say/alice/hello", {}, expect_json=True
        )


def test_redirect_is_blocked_and_never_followed():
    transport, connection, calls = transport_with(
        FakeResponse(302, headers={"Location": "https://evil.invalid/path"})
    )
    result = transport.list_rooms()
    assert not result.ok and result.error == "redirect_blocked"
    assert len(calls) == 1 and len(connection.requests) == 1


def test_health_and_rooms_are_known_get_endpoints():
    rooms, rooms_connection, _ = transport_with(FakeResponse(body=b"[]"))
    health, health_connection, _ = transport_with(FakeResponse(body=b"ok"))
    assert rooms.list_rooms().data == []
    assert health.health().data == "ok"
    assert rooms_connection.requests[0][1] == "/rooms?format=json"
    assert health_connection.requests[0][1] == "/healthz"


def test_long_poll_and_response_size_are_bounded():
    transport, _, _ = transport_with(FakeResponse())
    with pytest.raises(ValueError):
        transport.read_room("lobby", wait=11)
    with pytest.raises(ValueError):
        TechnocoreTransport("https://example.invalid", timeout_seconds=61)


def test_rate_limit_returns_structured_retry_after_without_retrying():
    transport, connection, calls = transport_with(
        FakeResponse(429, headers={"Retry-After": "17"})
    )
    result = transport.read_room("lobby")
    assert not result.ok
    assert result.error == "rate_limited" and result.retry_after_seconds == 17
    assert len(calls) == 1 and len(connection.requests) == 1


def test_default_tls_context_keeps_certificate_verification_enabled():
    transport, _, calls = transport_with(FakeResponse())
    transport.health()
    context = calls[0][3]
    assert context.check_hostname is True
    assert context.verify_mode.name == "CERT_REQUIRED"


def test_transport_result_can_be_explicitly_adapted_into_watcher(tmp_path):
    transport, _, _ = transport_with(FakeResponse(body=b'{"items":[{"synthetic":true}]}'))
    result = transport.read_room("lobby")
    store = EventStore(tmp_path / "events.sqlite3")
    store.initialize()
    watcher = Watcher(store)

    def synthetic_adapter(payload):
        assert payload["items"][0]["synthetic"] is True
        return [{
            "room": "lobby",
            "sequence": 1,
            "timestamp": "2026-01-02T03:04:05Z",
            "sender_name": "alice",
            "text": "synthetic only",
        }]

    processed = watcher.process_transport_result(result, synthetic_adapter)
    assert len(processed) == 1 and processed[0][1] is True
