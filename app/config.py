"""Central configuration for deterministic scanner rules."""

from dataclasses import dataclass, field

DEFAULT_PRIVILEGED_NAMES = frozenset(
    {"flop_labs", "technocore", "admin", "moderator", "official", "support"}
)


@dataclass(frozen=True, slots=True)
class WatchtowerConfig:
    privileged_names: frozenset[str] = field(
        default_factory=lambda: DEFAULT_PRIVILEGED_NAMES
    )
    technocore_hosts: frozenset[str] = field(
        default_factory=lambda: frozenset({"technocore.chat"})
    )

    def __post_init__(self) -> None:
        if any(not host or "://" in host or "/" in host for host in self.technocore_hosts):
            raise ValueError("Technocore hosts must be bare hostnames")
