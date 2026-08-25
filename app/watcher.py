"""Transport-independent input → parser → scanner → storage pipeline."""

from collections.abc import Callable, Iterable, Mapping
from typing import TYPE_CHECKING, Any

from .config import WatchtowerConfig
from .models import SecurityEvent
from .parser import parse_message
from .risk import RiskEngine
from .scanner import scan_message
from .storage import EventStore

if TYPE_CHECKING:
    from .transport import TransportResult


class Watcher:
    def __init__(self, store: EventStore, config: WatchtowerConfig | None = None) -> None:
        self.store = store
        self.config = config or WatchtowerConfig()
        self.risk_engine = RiskEngine(self.config)

    def process(self, data: Mapping[str, Any]) -> tuple[SecurityEvent, bool]:
        message = parse_message(data)
        event = scan_message(message, self.config)
        inserted = self.store.insert(event, self.risk_engine)
        return event, inserted

    def process_many(
        self, messages: Iterable[Mapping[str, Any]]
    ) -> list[tuple[SecurityEvent, bool]]:
        """Process already-adapted transport records without retaining the batch."""

        return [self.process(message) for message in messages]

    def process_transport_result(
        self,
        result: "TransportResult",
        adapter: Callable[[Any], Iterable[Mapping[str, Any]]],
    ) -> list[tuple[SecurityEvent, bool]]:
        """Adapt a successful in-memory read response and process its messages.

        The adapter is explicit because Technocore JSON field semantics must be
        documented before Watchtower maps them to identity claims.
        """

        if not result.ok:
            return []
        return self.process_many(adapter(result.data))
