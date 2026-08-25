"""Normalize untrusted mappings without classifying their security meaning."""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from .models import NormalizedMessage


class ParseError(ValueError):
    pass


def _timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ParseError("invalid timestamp") from exc
    else:
        raise ParseError("timestamp must be an ISO-8601 string or datetime")
    if result.tzinfo is None or result.utcoffset() is None:
        raise ParseError("timestamp must include a timezone")
    return result.astimezone(UTC)


def parse_message(data: Mapping[str, Any]) -> NormalizedMessage:
    """Parse a transport-neutral message mapping into the internal model."""

    try:
        room = data["room"]
        sequence = data["sequence"]
        sender_name = data["sender_name"]
        text = data["text"]
        timestamp = data["timestamp"]
    except KeyError as exc:
        raise ParseError(f"missing required field: {exc.args[0]}") from exc

    if not isinstance(room, str) or not room:
        raise ParseError("room must be a non-empty string")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise ParseError("sequence must be a non-negative integer")
    if not isinstance(sender_name, str) or not sender_name:
        raise ParseError("sender_name must be a non-empty string")
    if not isinstance(text, str):
        raise ParseError("text must be a string")

    did = data.get("did")
    if did is not None and not isinstance(did, str):
        raise ParseError("did must be a string or null")
    # Presence is intentionally separate from signature claims.
    signed = data.get("signed_identity_present", False)
    if not isinstance(signed, bool):
        raise ParseError("signed_identity_present must be a boolean")
    if signed and not did:
        raise ParseError("signed_identity_present requires identity data")

    return NormalizedMessage(
        room=room,
        sequence=sequence,
        timestamp=_timestamp(timestamp),
        sender_name=sender_name,
        did=did,
        signed_identity_present=signed,
        text=text,
    )
