"""Bounded in-process publish/subscribe for metadata-only SSE updates."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class StreamEvent:
    event: str
    data: dict[str, Any]
    event_id: int | None = None


class EventBroker:
    """Fan out persisted observations and debounced aggregate snapshots."""

    def __init__(
        self,
        aggregate_snapshot: Callable[
            [], tuple[dict[str, object], list[dict[str, object]]]
        ],
        *,
        history_size: int = 100,
        subscriber_queue_size: int = 100,
        aggregate_delay: float = 1.0,
    ) -> None:
        if not 1 <= history_size <= 500:
            raise ValueError("history_size must be between 1 and 500")
        if not 1 <= subscriber_queue_size <= 500:
            raise ValueError("subscriber_queue_size must be between 1 and 500")
        if not 0 <= aggregate_delay <= 5:
            raise ValueError("aggregate_delay must be between 0 and 5 seconds")
        self.aggregate_snapshot = aggregate_snapshot
        self.history: deque[StreamEvent] = deque(maxlen=history_size)
        self.subscriber_queue_size = subscriber_queue_size
        self.aggregate_delay = aggregate_delay
        self._subscribers: set[asyncio.Queue[StreamEvent]] = set()
        self._aggregate_task: asyncio.Task[None] | None = None

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def subscribe(
        self, last_event_id: int | None = None
    ) -> tuple[asyncio.Queue[StreamEvent], list[StreamEvent]]:
        queue: asyncio.Queue[StreamEvent] = asyncio.Queue(
            maxsize=self.subscriber_queue_size
        )
        self._subscribers.add(queue)
        replay = []
        if last_event_id is not None:
            replay = [
                event
                for event in self.history
                if event.event_id is not None and event.event_id > last_event_id
            ]
        return queue, replay

    def unsubscribe(self, queue: asyncio.Queue[StreamEvent]) -> None:
        self._subscribers.discard(queue)

    def publish_observation(self, data: dict[str, Any]) -> None:
        event_id = data.get("id")
        if not isinstance(event_id, int) or isinstance(event_id, bool) or event_id <= 0:
            raise ValueError("observation stream events require a positive integer id")
        event = StreamEvent("observation", dict(data), event_id)
        self.history.append(event)
        self._broadcast(event)
        if self._aggregate_task is None or self._aggregate_task.done():
            self._aggregate_task = asyncio.create_task(self._publish_aggregates())

    def current_aggregates(self) -> tuple[dict[str, object], list[dict[str, object]]]:
        return self.aggregate_snapshot()

    async def close(self) -> None:
        if self._aggregate_task is not None and not self._aggregate_task.done():
            self._aggregate_task.cancel()
            try:
                await self._aggregate_task
            except asyncio.CancelledError:
                pass

    async def _publish_aggregates(self) -> None:
        await asyncio.sleep(self.aggregate_delay)
        summary, rooms = await asyncio.to_thread(self.aggregate_snapshot)
        self._broadcast(StreamEvent("summary", summary))
        self._broadcast(StreamEvent("room_update", {"rooms": rooms}))

    def _broadcast(self, event: StreamEvent) -> None:
        for queue in tuple(self._subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(event)
