"""In-memory runtime state and conservative allowlisted polling worker."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .adapter import adapt_room_response
from .transport import TechnocoreTransport
from .watcher import Watcher


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class RuntimeState:
    monitored_rooms: tuple[str, ...]
    watcher_started: datetime = field(default_factory=utc_now)
    last_poll_attempt: datetime | None = None
    last_successful_poll: datetime | None = None
    last_transport_error: str | None = None
    total_transport_failures: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_attempt(self) -> None:
        with self._lock:
            self.last_poll_attempt = utc_now()

    def record_success(self) -> None:
        with self._lock:
            self.last_successful_poll = utc_now()

    def clear_error(self) -> None:
        with self._lock:
            self.last_transport_error = None

    def record_failure(self, error: str) -> None:
        with self._lock:
            self.last_transport_error = error
            self.total_transport_failures += 1

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "watcher_started": self.watcher_started,
                "last_poll_attempt": self.last_poll_attempt,
                "last_successful_poll": self.last_successful_poll,
                "last_transport_error": self.last_transport_error,
                "monitored_rooms": self.monitored_rooms,
                "total_transport_failures": self.total_transport_failures,
            }


class PollingWorker:
    def __init__(
        self,
        transport: TechnocoreTransport,
        watcher: Watcher,
        state: RuntimeState,
        *,
        poll_interval: float = 30.0,
        long_poll_wait: int = 2,
        batch_limit: int = 5,
        max_backoff: float = 120.0,
        observation_publisher: Callable[[dict[str, object]], None] | None = None,
    ) -> None:
        if not 5 <= poll_interval <= 3600:
            raise ValueError("poll_interval must be between 5 and 3600 seconds")
        if not 0 <= long_poll_wait <= 10:
            raise ValueError("long_poll_wait must be between 0 and 10")
        self.transport = transport
        self.watcher = watcher
        self.state = state
        self.poll_interval = poll_interval
        self.long_poll_wait = long_poll_wait
        self.batch_limit = max(1, min(batch_limit, 20))
        self.max_backoff = max(10.0, min(max_backoff, 300.0))
        self.observation_publisher = observation_publisher
        self._last_sequences = {room: 0 for room in state.monitored_rooms}
        self._retry_after_hint = 0

    async def poll_once(self) -> bool:
        all_successful = True
        for room in self.state.monitored_rooms:
            self.state.record_attempt()
            result = await asyncio.to_thread(
                self.transport.read_room,
                room,
                since=self._last_sequences[room],
                wait=self.long_poll_wait,
                limit=self.batch_limit,
            )
            if not result.ok:
                self.state.record_failure(result.error or "unknown_transport_error")
                if result.retry_after_seconds is not None:
                    self._retry_after_hint = max(
                        self._retry_after_hint, result.retry_after_seconds
                    )
                all_successful = False
                continue
            def adapter(payload: Any, selected_room: str = room):
                return adapt_room_response(payload, selected_room)

            processed = self.watcher.process_transport_result(result, adapter)
            if self.observation_publisher is not None:
                for event, inserted in processed:
                    if not inserted:
                        continue
                    stored = self.watcher.store.api_event_by_room_sequence(
                        event.message.room, event.message.sequence
                    )
                    if stored is not None:
                        self.observation_publisher(stored)
            if processed:
                self._last_sequences[room] = max(
                    event.message.sequence for event, _ in processed
                )
            self.state.record_success()
        if all_successful:
            self.state.clear_error()
        return all_successful

    async def run(self, stop_event: asyncio.Event) -> None:
        failures = 0
        while not stop_event.is_set():
            successful = await self.poll_once()
            failures = 0 if successful else min(failures + 1, 4)
            delay = min(
                max(self.poll_interval * (2**failures), self._retry_after_hint),
                self.max_backoff,
            )
            self._retry_after_hint = 0
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=delay)
            except TimeoutError:
                pass
