from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, raw: str | None) -> "Severity":
        if not raw:
            return cls.UNKNOWN
        value = raw.strip().upper()
        # Veracode uses "Very High" which corresponds to CRITICAL.
        if value in ("VERY HIGH", "VERY-HIGH", "VERYHIGH"):
            return cls.CRITICAL
        if value == "INFORMATIONAL":
            return cls.LOW
        for s in cls:
            if s.value == value:
                return s
        return cls.UNKNOWN

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.UNKNOWN: 4,
        }
        return order[self]


@dataclass(frozen=True)
class VulnEntry:
    group_id: str
    artifact_id: str
    vuln_version: str
    cve: str = ""
    severity: Severity = Severity.UNKNOWN
    notes: str = ""
    fixed_versions: tuple[str, ...] = ()

    @property
    def ga(self) -> str:
        return f"{self.group_id}:{self.artifact_id}"


Strategy = Literal[
    "bump_direct",
    "bump_parent",
    "bump_managed",
    "dm_override",
    "exclusion_and_direct",
    "bump_bom_import",
]


Verdict = Literal["success", "retry", "gave_up", "skip"]


@dataclass
class AttemptLog:
    ga: str
    from_version: str
    to_version: str
    strategy: Strategy | None
    pipeline_exit: int | None
    stderr_excerpt: str
    verdict: Verdict
    note: str = ""


@dataclass
class DepOutcome:
    """Aggregated outcome for one vulnerable dependency across attempts."""
    entry: VulnEntry
    attempts: list[AttemptLog] = field(default_factory=list)
    final_verdict: Verdict = "skip"
    final_version: str | None = None
    final_strategy: Strategy | None = None


@dataclass
class RunReport:
    repo_url: str
    branch: str | None = None
    pr_url: str | None = None
    outcomes: list[DepOutcome] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    @property
    def succeeded(self) -> list[DepOutcome]:
        return [o for o in self.outcomes if o.final_verdict == "success"]

    @property
    def gave_up(self) -> list[DepOutcome]:
        return [o for o in self.outcomes if o.final_verdict == "gave_up"]

    @property
    def skipped(self) -> list[DepOutcome]:
        return [o for o in self.outcomes if o.final_verdict == "skip"]
