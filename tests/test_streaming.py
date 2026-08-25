import asyncio
import json

from fastapi.testclient import TestClient
from starlette.requests import Request

from app.dashboard import DashboardSettings, create_app
from app.parser import parse_message
from app.scanner import scan_message
from app.streaming import EventBroker

RAW_TEXT = "raw body https://message-derived.invalid/private"
VERCEL_ORIGIN = "https://technocore-watchtower.vercel.app"


def make_app(tmp_path, *, heartbeat=0.05):
    return create_app(
        DashboardSettings(
            database_path=tmp_path / "events.sqlite3",
            monitored_rooms=("lobby",),
            polling_enabled=False,
            sse_heartbeat_seconds=heartbeat,
        )
    )


def stream_endpoint(app):
    return next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", None) == "/api/v1/stream"
    )


def request(headers=None):
    selected = [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": "/api/v1/stream",
            "raw_path": b"/api/v1/stream",
            "query_string": b"",
            "headers": selected,
            "client": ("127.0.0.1", 1),
            "server": ("test", 443),
        }
    )


def test_stream_headers_get_only_and_exact_cors(tmp_path):
    app = make_app(tmp_path)

    async def scenario():
        response = await stream_endpoint(app)(request({"origin": VERCEL_ORIGIN}))
        assert response.media_type == "text/event-stream"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-accel-buffering"] == "no"
        assert response.headers["access-control-allow-origin"] == VERCEL_ORIGIN
        iterator = response.body_iterator
        assert "event: summary" in await anext(iterator)
        await iterator.aclose()

    asyncio.run(scenario())
    with TestClient(app) as client:
        assert client.post("/api/v1/stream").status_code == 405
        assert (
            client.get("/api/v1/stream", headers={"origin": "https://example.com"}).status_code
            == 403
        )


def test_persisted_metadata_stream_excludes_raw_content_and_urls(tmp_path):
    app = make_app(tmp_path)
    event = scan_message(
        parse_message(
            {
                "room": "lobby",
                "sequence": 7,
                "timestamp": "2026-01-02T03:04:05Z",
                "sender_name": "alice",
                "text": RAW_TEXT,
            }
        )
    )
    assert app.state.store.insert(event)
    stored = app.state.store.api_event_by_room_sequence("lobby", 7)
    assert stored is not None

    async def scenario():
        response = await stream_endpoint(app)(request())
        iterator = response.body_iterator
        await anext(iterator)
        await anext(iterator)
        app.state.broker.publish_observation(stored)
        chunk = await asyncio.wait_for(anext(iterator), timeout=1)
        assert "event: observation" in chunk
        assert "id: 1" in chunk
        assert RAW_TEXT not in chunk
        assert "message-derived.invalid" not in chunk
        payload = json.loads(next(line[6:] for line in chunk.splitlines() if line.startswith("data: ")))
        assert "text" not in payload and "urls" not in payload
        await iterator.aclose()
        await app.state.broker.close()

    asyncio.run(scenario())


def test_stream_heartbeat_and_disconnect_cleanup(tmp_path):
    app = make_app(tmp_path)

    async def scenario():
        response = await stream_endpoint(app)(request())
        iterator = response.body_iterator
        await anext(iterator)
        await anext(iterator)
        assert app.state.broker.subscriber_count == 1
        heartbeat = await asyncio.wait_for(anext(iterator), timeout=0.5)
        assert "event: heartbeat" in heartbeat
        assert '"ts":' in heartbeat
        await iterator.aclose()
        assert app.state.broker.subscriber_count == 0

    asyncio.run(scenario())


def test_multiple_clients_and_bounded_replay(tmp_path):
    app = make_app(tmp_path)

    async def scenario():
        first = await stream_endpoint(app)(request())
        second = await stream_endpoint(app)(request())
        first_iterator = first.body_iterator
        second_iterator = second.body_iterator
        await anext(first_iterator)
        await anext(second_iterator)
        assert app.state.broker.subscriber_count == 2
        await first_iterator.aclose()
        await second_iterator.aclose()
        assert app.state.broker.subscriber_count == 0

        broker = EventBroker(lambda: ({}, []), history_size=2, aggregate_delay=0)
        broker.publish_observation({"id": 1})
        broker.publish_observation({"id": 2})
        broker.publish_observation({"id": 3})
        queue, replay = broker.subscribe(last_event_id=1)
        assert [event.event_id for event in replay] == [2, 3]
        assert len(broker.history) == 2
        broker.unsubscribe(queue)
        await broker.close()

    asyncio.run(scenario())
