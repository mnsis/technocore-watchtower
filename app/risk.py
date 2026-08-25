"""Deterministic, event-scoped shadow risk evaluation.

The engine consumes metadata-only evidence and bounded recent context. Its score
is a calibration heuristic, not a probability or a reputation assessment.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass
from enum import StrEnum

from .config import WatchtowerConfig

ENGINE_VERSION = "risk-v2-shadow-1"
NORMALIZATION_VERSION = "name-nfkc-casefold-separators-v1"
REPEAT_WINDOW_MINUTES = 15
IDENTITY_WINDOW_HOURS = 1
BASELINE_WINDOW_HOURS = 24
BURST_FLOOR_PER_MINUTE = 10
CONTEXT_POINTS_CAP = 20

_SEPARATORS_RE = re.compile(r"[\s_.-]+")
_ASCII_SUBSTITUTIONS = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t"})
_MIN_FUZZY_LENGTH = 6


class ShadowClassification(StrEnum):
    NONE = "NONE"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ProtectedNameMatch(StrEnum):
    NONE = "NONE"
    EXACT = "EXACT"
    CONFUSABLE = "CONFUSABLE"


@dataclass(frozen=True, slots=True)
class EventEvidence:
    did_present: bool
    signed_identity_present: bool
    protected_name_match: ProtectedNameMatch
    write_capable_route: bool


@dataclass(frozen=True, slots=True)
class HistoricalContext:
    did_name_inconsistent: bool = False
    name_did_inconsistent: bool = False
    did_recent_name_count: int = 1
    name_recent_did_count: int = 0
    repeated_equivalent_signal_count: int = 0
    activity_count_1m: int = 0
    activity_baseline_median: float = 0.0
    activity_baseline_mad: float = 0.0
    activity_burst_threshold: int = BURST_FLOOR_PER_MINUTE
    collector_coverage_ratio: float = 0.0
    collector_coverage_sufficient: bool = False
    qualified_activity_burst: bool = False
    signal_room_count: int = 1

    @property
    def rapid_identity_name_inconsistency(self) -> bool:
        return self.did_name_inconsistent or self.name_did_inconsistent

    @property
    def repeated_risk_signal(self) -> bool:
        return self.repeated_equivalent_signal_count >= 2

    @property
    def cross_room_signal_propagation(self) -> bool:
        return self.signal_room_count >= 2

    def as_bounded_dict(self) -> dict[str, bool | float | int]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Contribution:
    code: str
    points: int
    family: str
    kind: str


@dataclass(frozen=True, slots=True)
class RiskEvaluation:
    engine_version: str
    normalization_version: str
    score: int
    classification: ShadowClassification
    contributions: tuple[Contribution, ...]
    context: HistoricalContext
    risk_families: tuple[str, ...]
    temporal_corroboration: bool
    gate_explanation: str | None = None


def normalize_sender_name(value: str) -> str:
    """Normalize a sender name using the versioned, deliberately narrow rules."""

    normalized = unicodedata.normalize("NFKC", value).casefold().strip()
    return _SEPARATORS_RE.sub("_", normalized).strip("_")


def _compact(value: str) -> str:
    return value.replace("_", "")


def _edit_distance_at_most_one(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1 or left == right:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right, strict=True)) == 1
    short, long = (left, right) if len(left) < len(right) else (right, left)
    index_short = index_long = differences = 0
    while index_short < len(short) and index_long < len(long):
        if short[index_short] == long[index_long]:
            index_short += 1
            index_long += 1
            continue
        differences += 1
        index_long += 1
        if differences > 1:
            return False
    return True


def protected_name_match(
    sender_name: str, config: WatchtowerConfig | None = None
) -> ProtectedNameMatch:
    """Return exact or narrowly bounded protected-name similarity."""

    selected_config = config or WatchtowerConfig()
    normalized = normalize_sender_name(sender_name)
    protected = {normalize_sender_name(name) for name in selected_config.privileged_names}
    if normalized in protected:
        return ProtectedNameMatch.EXACT

    compact = _compact(normalized)
    if not compact.isascii():
        return ProtectedNameMatch.NONE
    for candidate in protected:
        protected_compact = _compact(candidate)
        if len(protected_compact) < _MIN_FUZZY_LENGTH:
            continue
        if compact == protected_compact:
            return ProtectedNameMatch.CONFUSABLE
        substituted = compact.translate(_ASCII_SUBSTITUTIONS)
        substitutions = sum(a != b for a, b in zip(compact, substituted, strict=True))
        if substitutions == 1 and substituted == protected_compact:
            return ProtectedNameMatch.CONFUSABLE
        if _edit_distance_at_most_one(compact, protected_compact):
            return ProtectedNameMatch.CONFUSABLE
    return ProtectedNameMatch.NONE


class RiskEngine:
    """Versioned shadow engine with explicit evidence, context, and gates."""

    version = ENGINE_VERSION
    normalization_version = NORMALIZATION_VERSION

    def __init__(self, config: WatchtowerConfig | None = None) -> None:
        self.config = config or WatchtowerConfig()

    def event_evidence(
        self,
        *,
        sender_name: str,
        did_present: bool,
        signed_identity_present: bool,
        write_capable_route: bool,
    ) -> EventEvidence:
        match = (
            ProtectedNameMatch.NONE
            if signed_identity_present
            else protected_name_match(sender_name, self.config)
        )
        return EventEvidence(
            did_present=did_present,
            signed_identity_present=signed_identity_present,
            protected_name_match=match,
            write_capable_route=write_capable_route,
        )

    @staticmethod
    def risk_signal_codes(evidence: EventEvidence) -> tuple[str, ...]:
        codes: list[str] = []
        if evidence.protected_name_match is ProtectedNameMatch.EXACT:
            codes.append("UNSIGNED_PROTECTED_NAME_EXACT")
        elif evidence.protected_name_match is ProtectedNameMatch.CONFUSABLE:
            codes.append("UNSIGNED_PROTECTED_NAME_CONFUSABLE")
        if evidence.write_capable_route:
            codes.append("WRITE_CAPABLE_ROUTE")
        return tuple(codes)

    def evaluate(
        self, evidence: EventEvidence, context: HistoricalContext | None = None
    ) -> RiskEvaluation:
        selected_context = context or HistoricalContext()
        contributions: list[Contribution] = []
        families: set[str] = set()

        if evidence.did_present:
            contributions.append(Contribution("DID_PRESENT", 0, "informational", "evidence"))
        if evidence.protected_name_match is ProtectedNameMatch.EXACT:
            contributions.append(
                Contribution("UNSIGNED_PROTECTED_NAME_EXACT", 25, "identity", "evidence")
            )
            families.add("identity")
        elif evidence.protected_name_match is ProtectedNameMatch.CONFUSABLE:
            contributions.append(
                Contribution("UNSIGNED_PROTECTED_NAME_CONFUSABLE", 15, "identity", "evidence")
            )
            families.add("identity")
        if evidence.write_capable_route:
            contributions.append(
                Contribution("WRITE_CAPABLE_ROUTE", 35, "capability", "evidence")
            )
            families.add("capability")
        if families == {"identity", "capability"}:
            contributions.append(
                Contribution(
                    "IDENTITY_CAPABILITY_CORRELATION", 15, "correlation", "interaction"
                )
            )

        if families:
            candidates = (
                (
                    selected_context.rapid_identity_name_inconsistency,
                    Contribution("RAPID_IDENTITY_NAME_INCONSISTENCY", 10, "context", "modifier"),
                ),
                (
                    selected_context.repeated_risk_signal,
                    Contribution("REPEATED_RISK_SIGNAL", 10, "context", "modifier"),
                ),
                (
                    selected_context.qualified_activity_burst,
                    Contribution("QUALIFIED_ACTIVITY_BURST", 10, "context", "modifier"),
                ),
                (
                    selected_context.cross_room_signal_propagation,
                    Contribution("CROSS_ROOM_SIGNAL_PROPAGATION", 5, "context", "modifier"),
                ),
            )
            context_points = 0
            for applies, contribution in candidates:
                if applies and context_points + contribution.points <= CONTEXT_POINTS_CAP:
                    contributions.append(contribution)
                    context_points += contribution.points

        score = min(100, sum(item.points for item in contributions))
        temporal = any(item.kind == "modifier" for item in contributions)
        classification, gate_explanation = self._classify(
            score=score,
            informational=evidence.did_present,
            family_count=len(families),
            temporal_corroboration=temporal,
        )
        return RiskEvaluation(
            engine_version=self.version,
            normalization_version=self.normalization_version,
            score=score,
            classification=classification,
            contributions=tuple(contributions),
            context=selected_context,
            risk_families=tuple(sorted(families)),
            temporal_corroboration=temporal,
            gate_explanation=gate_explanation,
        )

    @staticmethod
    def _classify(
        *, score: int, informational: bool, family_count: int, temporal_corroboration: bool
    ) -> tuple[ShadowClassification, str | None]:
        if score == 0:
            return (
                ShadowClassification.INFO if informational else ShadowClassification.NONE,
                None,
            )
        if score < 30:
            return ShadowClassification.LOW, None
        if score < 60:
            return ShadowClassification.MEDIUM, None
        if family_count < 2:
            return (
                ShadowClassification.MEDIUM,
                "HIGH requires at least two independent risk families.",
            )
        if score < 85:
            return ShadowClassification.HIGH, None
        if not temporal_corroboration:
            return (
                ShadowClassification.HIGH,
                "CRITICAL requires recent temporal corroboration.",
            )
        return ShadowClassification.CRITICAL, None
