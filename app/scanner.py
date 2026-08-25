"""Pure, deterministic scanning of normalized messages; performs no I/O."""

import hashlib
import re
from urllib.parse import unquote, urlsplit

from .config import WatchtowerConfig
from .models import NormalizedMessage, SecurityEvent, SecurityFlag, Severity

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,;:!?)]}"
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")


def extract_urls(text: str) -> tuple[str, ...]:
    """Extract HTTP(S) URL text without resolving or contacting any host."""

    return tuple(match.group(0).rstrip(_TRAILING_PUNCTUATION) for match in _URL_RE.finditer(text))


def _decoded_path_segments(path: str) -> tuple[str, ...] | None:
    """Decode each path component once, rejecting ambiguous encoded separators.

    Query strings and fragments do not affect route classification. Percent escapes
    are decoded exactly once; a decoded slash/backslash or control byte makes the
    path too ambiguous to classify.
    """

    segments: list[str] = []
    for raw in path.split("/")[1:]:
        try:
            decoded = unquote(raw, errors="strict")
        except UnicodeDecodeError:
            return None
        if not decoded or "/" in decoded or "\\" in decoded or any(ord(c) < 32 for c in decoded):
            return None
        segments.append(decoded)
    return tuple(segments)


def _valid_name(value: str) -> bool:
    return _NAME_RE.fullmatch(value) is not None


def _is_technocore_write_url(url: str, config: WatchtowerConfig) -> bool:
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return False
    if not host or host.casefold() not in {item.casefold() for item in config.technocore_hosts}:
        return False
    segments = _decoded_path_segments(parts.path)
    if segments is None:
        return False

    # /r/<room>/say/<nick>/<text...>
    if len(segments) >= 5 and segments[0] == "r" and segments[2] == "say":
        return _valid_name(segments[1]) and _valid_name(segments[3])
    # /r/<room>/say-signed/<did>/<sig>/<nonce>/<text...>
    if len(segments) >= 7 and segments[0] == "r" and segments[2] == "say-signed":
        return _valid_name(segments[1]) and all(segments[index] for index in (3, 4, 5, 6))
    # /kv/topic/<room>/set/<text...>
    if len(segments) >= 5 and segments[:2] == ("kv", "topic") and segments[3] == "set":
        return _valid_name(segments[2])
    # /kv/<namespace>/<key>/set/<value...>
    if len(segments) >= 5 and segments[0] == "kv" and segments[3] == "set":
        return _valid_name(segments[1]) and _valid_name(segments[2])
    # /kv/<namespace>/<key>/set-signed/<did>/<sig>/<nonce>/<value...>
    if len(segments) >= 8 and segments[0] == "kv" and segments[3] == "set-signed":
        return (
            _valid_name(segments[1])
            and _valid_name(segments[2])
            and all(segments[index] for index in (4, 5, 6, 7))
        )
    return False


def scan_message(
    message: NormalizedMessage, config: WatchtowerConfig | None = None
) -> SecurityEvent:
    config = config or WatchtowerConfig()
    flags: list[SecurityFlag] = []
    urls = extract_urls(message.text)

    did_present = bool(message.did and message.did.startswith("did:key:"))
    if did_present:
        flags.append(SecurityFlag.DID_PRESENT)

    privileged = message.sender_name.casefold() in {
        name.casefold() for name in config.privileged_names
    }
    if privileged and not message.signed_identity_present:
        flags.append(SecurityFlag.UNSIGNED_PRIVILEGED_NAME)

    if any(_is_technocore_write_url(url, config) for url in urls):
        flags.append(SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL)

    if (
        SecurityFlag.UNSIGNED_PRIVILEGED_NAME in flags
        and SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL in flags
    ):
        flags.append(SecurityFlag.SUSPICIOUS_COMBINATION)

    if SecurityFlag.SUSPICIOUS_COMBINATION in flags:
        severity = Severity.HIGH
    elif SecurityFlag.POTENTIAL_TECHNOCORE_WRITE_URL in flags:
        severity = Severity.MEDIUM
    elif SecurityFlag.UNSIGNED_PRIVILEGED_NAME in flags:
        severity = Severity.LOW
    elif SecurityFlag.DID_PRESENT in flags:
        severity = Severity.INFO
    else:
        severity = Severity.NONE

    return SecurityEvent(
        message=message,
        urls=urls,
        flags=tuple(flags),
        severity=severity,
        message_sha256=hashlib.sha256(message.text.encode("utf-8")).hexdigest(),
    )
