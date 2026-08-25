"""Minimal adapter for the observed Technocore JSON room envelope."""

from collections.abc import Iterator, Mapping
from typing import Any

from .transport import ROOM_RE


def adapt_room_response(payload: Any, expected_room: str) -> Iterator[dict[str, Any]]:
    """Yield normalized parser inputs from observed, unambiguous fields only.

    Mapping: envelope `room`; record `seq` → sequence, `ts` → timestamp,
    `from` → sender_name, and `text` → ephemeral scanner input. The observed
    `nonce` and all unknown fields are ignored. No DID or signature status is
    inferred because their live JSON semantics have not been established.
    """

    if ROOM_RE.fullmatch(expected_room) is None or not isinstance(payload, Mapping):
        return
    if payload.get("room") != expected_room or not isinstance(payload.get("messages"), list):
        return
    for record in payload["messages"]:
        if not isinstance(record, Mapping):
            continue
        sequence = record.get("seq")
        timestamp = record.get("ts")
        sender = record.get("from")
        text = record.get("text")
        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 0
            or not isinstance(timestamp, str)
            or not isinstance(sender, str)
            or not sender
            or not isinstance(text, str)
        ):
            continue
        yield {
            "room": expected_room,
            "sequence": sequence,
            "timestamp": timestamp,
            "sender_name": sender,
            "did": None,
            "signed_identity_present": False,
            "text": text,
        }
