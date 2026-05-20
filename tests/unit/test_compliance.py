from __future__ import annotations

import json
from pathlib import Path

import pytest

from silent_updater.inputs.compliance import ComplianceConfig, load_compliance


def test_load_minimal(tmp_path: Path) -> None:
    p = tmp_path / "c.json"
    p.write_text(json.dumps({}), encoding="utf-8")
    cfg = load_compliance(p)
    assert cfg.update_strategy == "patch_minor"
    assert cfg.exceptions == []
    assert cfg.max_attempts_per_dep == 5


def test_load_full(tmp_path: Path) -> None:
    data = {
        "update_strategy": "patch",
        "exceptions": [{"ga": "org.foo:bar", "reason": "breaks X"}],
        "version_pins": {"a:b": "<3.0.0"},
        "max_attempts_per_dep": 3,
        "branch_template": "deps/{date}",
        "pr_target_branch": "develop",
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    cfg = load_compliance(p)
    assert cfg.update_strategy == "patch"
    assert cfg.is_excepted("org.foo:bar") == (True, "breaks X")
    assert cfg.is_excepted("missing:dep") == (False, "")
    assert cfg.pin_for("a:b") == "<3.0.0"
    assert cfg.max_attempts_per_dep == 3


def test_invalid_strategy_rejected(tmp_path: Path) -> None:
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"update_strategy": "wild"}), encoding="utf-8")
    with pytest.raises(Exception):
        load_compliance(p)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_compliance(tmp_path / "nope.json")
