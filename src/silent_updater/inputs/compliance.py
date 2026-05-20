from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


UpdateStrategy = Literal["patch", "patch_minor", "any"]


class Exception_(BaseModel):
    ga: str
    reason: str = ""


class ComplianceConfig(BaseModel):
    update_strategy: UpdateStrategy = "patch_minor"
    exceptions: list[Exception_] = Field(default_factory=list)
    version_pins: dict[str, str] = Field(default_factory=dict)
    max_attempts_per_dep: int = 5
    branch_template: str = "deps/silent-update-{date}"
    pr_target_branch: str = "main"

    def is_excepted(self, ga: str) -> tuple[bool, str]:
        for e in self.exceptions:
            if e.ga == ga:
                return True, e.reason
        return False, ""

    def pin_for(self, ga: str) -> str | None:
        return self.version_pins.get(ga)


def load_compliance(path: str | Path) -> ComplianceConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Compliance config not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    return ComplianceConfig.model_validate(data)
