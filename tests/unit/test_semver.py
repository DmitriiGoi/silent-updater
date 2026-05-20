from __future__ import annotations

import pytest

from silent_updater.semver import (
    Version,
    allowed_by_strategy,
    classify_bump,
    is_strictly_greater,
    satisfies_pin,
)


@pytest.mark.parametrize("text,expected", [
    ("1.2.3", (1, 2, 3)),
    ("2.0", (2, 0, 0)),
    ("4", (4, 0, 0)),
    ("3.10.0-SNAPSHOT", (3, 10, 0)),
    ("5.3.20.RELEASE", (5, 3, 20)),
    ("2.13.0.Final", (2, 13, 0)),
])
def test_parse_valid(text: str, expected: tuple[int, int, int]) -> None:
    v = Version.parse(text)
    assert v is not None
    assert (v.major, v.minor, v.patch) == expected


@pytest.mark.parametrize("text", ["", "v1", "abc"])
def test_parse_invalid(text: str) -> None:
    assert Version.parse(text) is None


@pytest.mark.parametrize("from_v,to_v,expected", [
    ("1.0.0", "1.0.1", "patch"),
    ("1.0.0", "1.1.0", "minor"),
    ("1.0.0", "2.0.0", "major"),
    ("2.13.0", "2.13.5", "patch"),
    ("2.6.0", "2.7.18", "minor"),
    ("1.0.0", "1.0.0", "unknown"),
])
def test_classify_bump(from_v: str, to_v: str, expected: str) -> None:
    assert classify_bump(from_v, to_v) == expected


def test_strictly_greater() -> None:
    assert is_strictly_greater("3.14.0", "3.10")
    assert is_strictly_greater("2.13.5", "2.13.0")
    assert not is_strictly_greater("3.10", "3.14.0")
    assert not is_strictly_greater("3.10", "3.10")


@pytest.mark.parametrize("version,pin,expected", [
    ("5.3.20", "<6.0.0", True),
    ("6.0.0", "<6.0.0", False),
    ("1.5.0", ">=1.0.0,<2.0.0", True),
    ("2.0.0", ">=1.0.0,<2.0.0", False),
    ("0.9.0", ">=1.0.0,<2.0.0", False),
    ("1.0.0", "<=1.0.0", True),
    ("1.0.1", "<=1.0.0", False),
    ("2.7.18", None, True),
    ("2.7.18", "", True),
])
def test_satisfies_pin(version: str, pin: str | None, expected: bool) -> None:
    assert satisfies_pin(version, pin) is expected


@pytest.mark.parametrize("from_v,to_v,strategy,expected", [
    ("1.0.0", "1.0.1", "patch", True),
    ("1.0.0", "1.1.0", "patch", False),
    ("1.0.0", "1.1.0", "patch_minor", True),
    ("1.0.0", "2.0.0", "patch_minor", False),
    ("1.0.0", "2.0.0", "any", True),
])
def test_allowed_by_strategy(from_v: str, to_v: str, strategy: str, expected: bool) -> None:
    assert allowed_by_strategy(from_v, to_v, strategy) is expected
