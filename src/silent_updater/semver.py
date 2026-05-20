from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

BumpKind = Literal["patch", "minor", "major", "unknown"]

# Match leading X.Y.Z; tolerates suffixes like -SNAPSHOT, .RELEASE, .Final, +meta
_VERSION_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[.\-+].*)?$")


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int
    raw: str = ""

    @classmethod
    def parse(cls, text: str) -> "Version | None":
        if not text:
            return None
        m = _VERSION_RE.match(text.strip())
        if not m:
            return None
        major = int(m.group(1))
        minor = int(m.group(2) or 0)
        patch = int(m.group(3) or 0)
        return cls(major=major, minor=minor, patch=patch, raw=text.strip())

    def __str__(self) -> str:
        return self.raw or f"{self.major}.{self.minor}.{self.patch}"


def classify_bump(from_v: str, to_v: str) -> BumpKind:
    a, b = Version.parse(from_v), Version.parse(to_v)
    if a is None or b is None:
        return "unknown"
    if b.major != a.major:
        return "major"
    if b.minor != a.minor:
        return "minor"
    if b.patch != a.patch:
        return "patch"
    return "unknown"


def is_strictly_greater(candidate: str, baseline: str) -> bool:
    a, b = Version.parse(candidate), Version.parse(baseline)
    if a is None or b is None:
        return False
    return (a.major, a.minor, a.patch) > (b.major, b.minor, b.patch)


# Crude version-pin DSL: "<6.0.0", "<=2.9", ">=1.0.0,<2.0.0"
_OP_RE = re.compile(r"\s*(<=|>=|<|>|==|=)\s*([\w.\-+]+)\s*")


def satisfies_pin(version: str, pin: str | None) -> bool:
    """Returns True if `version` matches the comma-separated pin expression.

    Examples:
      satisfies_pin("5.3.20", "<6.0.0") -> True
      satisfies_pin("6.0.0", "<6.0.0") -> False
      satisfies_pin("1.5.0", ">=1.0,<2.0") -> True
    """
    if not pin:
        return True
    v = Version.parse(version)
    if v is None:
        return False
    for part in pin.split(","):
        if not part.strip():
            continue
        m = _OP_RE.match(part)
        if not m:
            return False
        op, ref_raw = m.group(1), m.group(2)
        ref = Version.parse(ref_raw)
        if ref is None:
            return False
        cmp = (v.major, v.minor, v.patch)
        rcmp = (ref.major, ref.minor, ref.patch)
        if op == "<" and not (cmp < rcmp):
            return False
        if op == "<=" and not (cmp <= rcmp):
            return False
        if op == ">" and not (cmp > rcmp):
            return False
        if op == ">=" and not (cmp >= rcmp):
            return False
        if op in ("=", "==") and not (cmp == rcmp):
            return False
    return True


def allowed_by_strategy(from_v: str, to_v: str, strategy: str) -> bool:
    """strategy: 'patch' | 'patch_minor' | 'any'."""
    bump = classify_bump(from_v, to_v)
    if strategy == "any":
        return bump in ("patch", "minor", "major", "unknown")
    if strategy == "patch_minor":
        return bump in ("patch", "minor")
    if strategy == "patch":
        return bump == "patch"
    return False
