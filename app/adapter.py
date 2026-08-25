"""Minimal adapter for the observed Technocore JSON room envelope."""

import re
from collections.abc import Iterator, Mapping
from typing import Any

from .transport import ROOM_RE

DID_KEY_RE = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")


def adapt_room_response(payload: Any, expected_room: str) -> Iterator[dict[str, Any]]:
    """Yield normalized parser inputs from observed, unambiguous fields only.

    Mapping: envelope `room`; record `seq` → sequence, `ts` → timestamp,
    `from` → sender_name, and `text` → ephemeral scanner input. Technocore's
    documented JSON schema places the full Ed25519 `did:key` in `from` and adds
    an integer `nonce` when a message entered through the server's signed lane.
    This maps server-exposed signed metadata; it is not independent signature
    verification by Watchtower. All unknown fields are ignored.
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
        nonce = record.get("nonce")
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
        signed_did = (
            sender
            if DID_KEY_RE.fullmatch(sender)
            and not isinstance(nonce, bool)
            and isinstance(nonce, int)
            and nonce >= 0
            else None
        )
        yield {
            "room": expected_room,
            "sequence": sequence,
            "timestamp": timestamp,
            "sender_name": sender,
            "did": signed_did,
            "signed_identity_present": signed_did is not None,
            "text": text,
        }
