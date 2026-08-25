"""Normalized input and classified event models."""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum, StrEnum


class SecurityFlag(StrEnum):
    DID_PRESENT = "DID_PRESENT"
    UNSIGNED_PRIVILEGED_NAME = "UNSIGNED_PRIVILEGED_NAME"
    POTENTIAL_TECHNOCORE_WRITE_URL = "POTENTIAL_TECHNOCORE_WRITE_URL"
    SUSPICIOUS_COMBINATION = "SUSPICIOUS_COMBINATION"


class Severity(IntEnum):
    NONE = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4


@dataclass(frozen=True, slots=True)
class NormalizedMessage:
    room: str
    sequence: int
    timestamp: datetime
    sender_name: str
    did: str | None
    signed_identity_present: bool
    text: str

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        if self.sequence < 0:
            raise ValueError("sequence must be non-negative")


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    message: NormalizedMessage
    urls: tuple[str, ...]
    flags: tuple[SecurityFlag, ...]
    severity: Severity
    message_sha256: str

    @property
    def created_at(self) -> datetime:
        return datetime.now(UTC)
