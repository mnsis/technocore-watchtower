from datetime import UTC

import pytest

from app.parser import ParseError, parse_message


def message(**overrides):
    data = {
        "room": "synthetic-room",
        "sequence": 1,
        "timestamp": "2026-01-02T03:04:05Z",
        "sender_name": "alice",
        "text": "hello",
    }
    data.update(overrides)
    return data


def test_ordinary_unsigned_nickname_is_not_authenticated():
    parsed = parse_message(message())
    assert parsed.sender_name == "alice"
    assert parsed.did is None
    assert parsed.signed_identity_present is False
    assert parsed.timestamp.tzinfo == UTC


def test_did_presence_does_not_imply_signed_identity():
    parsed = parse_message(message(did="did:key:zSynthetic"))
    assert parsed.did == "did:key:zSynthetic"
    assert parsed.signed_identity_present is False


def test_signed_claim_requires_identity_data():
    with pytest.raises(ParseError):
        parse_message(message(signed_identity_present=True))
