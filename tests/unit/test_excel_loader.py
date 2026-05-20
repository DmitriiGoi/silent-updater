from __future__ import annotations

from pathlib import Path

import pytest
from openpyxl import Workbook

from silent_updater.inputs.excel_loader import ExcelFormatError, load_vulnerable_libs
from silent_updater.models import Severity


def _make_xlsx(tmp_path: Path, rows: list[list]) -> Path:
    wb = Workbook()
    ws = wb.active
    for row in rows:
        ws.append(row)
    path = tmp_path / "vulns.xlsx"
    wb.save(path)
    return path


def test_loads_basic(tmp_path: Path) -> None:
    path = _make_xlsx(tmp_path, [
        ["groupId", "artifactId", "vulnerableVersion", "cve", "severity"],
        ["org.apache.logging.log4j", "log4j-core", "2.14.1", "CVE-2021-44228", "CRITICAL"],
        ["com.fasterxml.jackson.core", "jackson-databind", "2.13.0", "CVE-2022-42003", "HIGH"],
    ])
    entries = load_vulnerable_libs(path)
    assert len(entries) == 2
    assert entries[0].ga == "org.apache.logging.log4j:log4j-core"
    assert entries[0].vuln_version == "2.14.1"
    assert entries[0].cve == "CVE-2021-44228"
    assert entries[0].severity == Severity.CRITICAL
    assert entries[1].severity == Severity.HIGH


def test_missing_required_column_raises(tmp_path: Path) -> None:
    path = _make_xlsx(tmp_path, [
        ["groupId", "artifactId"],
        ["a", "b"],
    ])
    with pytest.raises(ExcelFormatError, match="vulnerableVersion"):
        load_vulnerable_libs(path)


def test_blank_rows_skipped(tmp_path: Path) -> None:
    path = _make_xlsx(tmp_path, [
        ["groupId", "artifactId", "vulnerableVersion"],
        ["a", "b", "1.0"],
        [None, None, None],
        ["c", "d", "2.0"],
    ])
    entries = load_vulnerable_libs(path)
    assert [e.ga for e in entries] == ["a:b", "c:d"]


def test_partial_row_raises(tmp_path: Path) -> None:
    path = _make_xlsx(tmp_path, [
        ["groupId", "artifactId", "vulnerableVersion"],
        ["a", "b", None],
    ])
    with pytest.raises(ExcelFormatError, match="required"):
        load_vulnerable_libs(path)


def test_severity_default_unknown(tmp_path: Path) -> None:
    path = _make_xlsx(tmp_path, [
        ["groupId", "artifactId", "vulnerableVersion"],
        ["a", "b", "1.0"],
    ])
    entries = load_vulnerable_libs(path)
    assert entries[0].severity == Severity.UNKNOWN
