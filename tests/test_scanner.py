from app.config import WatchtowerConfig
from app.models import SecurityFlag, Severity
from app.parser import parse_message
from app.scanner import scan_message


def event(sender="alice", text="hello", did=None, signed=False, config=None):
    message = parse_message(
        {
            "room": "synthetic-room",
            "sequence": 1,
            "timestamp": "2026-01-02T03:04:05Z",
            "sender_name": sender,
            "did": did,
            "signed_identity_present": signed,
            "text": text,
        }
    )
    return scan_message(message, config)


SYNTHETIC_CONFIG = WatchtowerConfig(technocore_hosts=frozenset({"example.invalid"}))


def test_ordinary_unsigned_nickname_has_no_flags():
    result = event()
    assert result.flags == ()
    assert result.severity is Severity.NONE


def test_privileged_looking_unsigned_nickname_is_neutrally_flagged():
    result = event(sender="AdMiN")
    assert result.flags == (SecurityFlag.UNSIGNED_PRIVILEGED_NAME,)
    assert result.severity is Severity.LOW


def test_did_key_is_visible_but_not_called_verified():
    result = event(did="did:key:zSynthetic")
    assert SecurityFlag.DID_PRESENT in result.flags
    assert result.message.signed_identity_present is False


def test_harmless_url_is_extracted_without_write_flag():
    result = event(text="See https://example.invalid/docs.")
    assert result.urls == ("https://example.invalid/docs",)
    assert SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL not in result.flags


def test_url_extraction_does_not_use_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr("socket.socket.connect", forbidden)
    result = event(text="https://unreachable.invalid/a")
    assert result.urls == ("https://unreachable.invalid/a",)


def test_documented_unsigned_say_url_is_flagged():
    result = event(
        text="https://example.invalid/r/lobby/say/alice/hello",
        config=SYNTHETIC_CONFIG,
    )
    assert SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL in result.flags
    assert result.severity is Severity.MEDIUM


def test_documented_signed_say_url_is_flagged():
    result = event(
        text="https://example.invalid/r/lobby/say-signed/did%3Akey%3Az/sig/nonce/hello",
        config=SYNTHETIC_CONFIG,
    )
    assert SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL in result.flags


def test_documented_kv_set_url_is_flagged():
    result = event(
        text="https://example.invalid/kv/prefs/theme/set/dark?if=light",
        config=SYNTHETIC_CONFIG,
    )
    assert SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL in result.flags


def test_documented_signed_kv_set_url_is_flagged():
    result = event(
        text="https://example.invalid/kv/prefs/theme/set-signed/did%3Akey%3Az/sig/nonce/dark",
        config=SYNTHETIC_CONFIG,
    )
    assert SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL in result.flags


def test_topic_set_url_is_flagged():
    result = event(
        text="https://example.invalid/kv/topic/lobby/set/hello",
        config=SYNTHETIC_CONFIG,
    )
    assert SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL in result.flags


def test_combined_objective_indicators_raise_severity():
    result = event(
        sender="support",
        text="https://example.invalid/r/lobby/say/alice/hello",
        config=SYNTHETIC_CONFIG,
    )
    assert SecurityFlag.SUSPICIOUS_COMBINATION in result.flags
    assert result.severity is Severity.HIGH


def test_write_shape_on_unrelated_host_is_not_flagged():
    result = event(text="https://unrelated.invalid/r/lobby/say/alice/hello")
    assert SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL not in result.flags


def test_mixed_case_configured_hostname_and_explicit_port_are_supported():
    result = event(
        text="See https://EXAMPLE.INVALID:443/r/lobby/say/alice/hello.",
        config=SYNTHETIC_CONFIG,
    )
    assert SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL in result.flags
    assert result.urls[-1].endswith("hello")


def test_documented_read_routes_are_not_flagged():
    for url in (
        "https://example.invalid/r/lobby",
        "https://example.invalid/r/lobby?since=10&format=json",
        "https://example.invalid/rooms?format=json",
        "https://example.invalid/healthz",
        "https://example.invalid/openapi.json",
    ):
        assert SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL not in event(
            text=url, config=SYNTHETIC_CONFIG
        ).flags


def test_encoded_route_name_is_decoded_once_but_encoded_separator_is_rejected():
    encoded_name = event(
        text="https://example.invalid/r/lobby/%73ay/alice/hello",
        config=SYNTHETIC_CONFIG,
    )
    ambiguous = event(
        text="https://example.invalid/r/lobby/say/alice%2Fadmin/hello",
        config=SYNTHETIC_CONFIG,
    )
    assert SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL in encoded_name.flags
    assert SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL not in ambiguous.flags


def test_invalid_route_structure_and_malformed_url_are_not_flagged():
    for url in (
        "https://example.invalid/not/r/lobby/say/alice/hello",
        "https://example.invalid/r/INVALID/say/alice/hello",
        "https://example.invalid/r/lobby/say/alice",
        "https://[broken/r/lobby/say/alice/hello",
    ):
        assert SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL not in event(
            text=url, config=SYNTHETIC_CONFIG
        ).flags
