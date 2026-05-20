from __future__ import annotations

from pathlib import Path

import pytest
from openpyxl import Workbook

from silent_updater.inputs.excel_loader import load_vulnerable_libs
from silent_updater.inputs.veracode_loader import (
    _extract_versions,
    _parse_gav,
    is_veracode_format,
    load_veracode,
)
from silent_updater.models import Severity


VERACODE_HEADERS = [
    "Component name and version", "Component name", "Version", "Provenance",
    "Source Ref", "CVE Summary", "Overall Severity",
    # filler columns 8-16
    "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
    "Fixed Version",
]


def _make_xlsx(tmp_path: Path, headers: list, rows: list[list]) -> Path:
    wb = Workbook()
    ws = wb.active
    ws.append(headers)
    for r in rows:
        ws.append(r)
    p = tmp_path / "vulns.xlsx"
    wb.save(p)
    return p


def test_is_veracode_format_positive() -> None:
    assert is_veracode_format(VERACODE_HEADERS)


def test_is_veracode_format_negative() -> None:
    assert not is_veracode_format(["groupId", "artifactId", "vulnerableVersion"])


def test_parse_gav_three_parts() -> None:
    assert _parse_gav("org.foo:bar:1.2.3") == ("org.foo", "bar", "1.2.3")


def test_parse_gav_with_packaging() -> None:
    assert _parse_gav("org.foo:bar:jar:1.2.3") == ("org.foo", "bar", "1.2.3")


def test_parse_gav_with_classifier() -> None:
    assert _parse_gav("org.foo:bar:jar:sources:1.2.3") == ("org.foo", "bar", "1.2.3")


def test_parse_gav_invalid() -> None:
    with pytest.raises(ValueError):
        _parse_gav("just-name")


def test_extract_versions_clean() -> None:
    assert _extract_versions("5.19.3, 6.2.2") == ("5.19.3", "6.2.2")


def test_extract_versions_veracode_messy() -> None:
    blob = "5.19.3, 5.19.3 ? Version ? 5.19.3, 6.2.2, 6.2.2 ? Version ? 6.2.2"
    assert _extract_versions(blob) == ("5.19.3", "6.2.2")


def test_extract_versions_with_suffix() -> None:
    assert _extract_versions("2.13.0-SNAPSHOT, 3.0.0.Final") == (
        "2.13.0-SNAPSHOT", "3.0.0.Final",
    )


def test_extract_versions_empty() -> None:
    assert _extract_versions("") == ()
    assert _extract_versions("none") == ()


def test_load_basic_row(tmp_path: Path) -> None:
    p = _make_xlsx(tmp_path, VERACODE_HEADERS, [
        ["org.apache.activemq:activemq-broker:5.14.5", "activemq-broker", "5.14.5",
         "VERACODE", "CVE-2020-13920", "summary text", "High",
         "x", "x", "x", "x", "x", "x", "x", "x", "x",
         "5.19.3, 6.2.2"],
    ])
    entries = load_veracode(p)
    assert len(entries) == 1
    e = entries[0]
    assert e.group_id == "org.apache.activemq"
    assert e.artifact_id == "activemq-broker"
    assert e.vuln_version == "5.14.5"
    assert e.cve == "CVE-2020-13920"
    assert e.severity == Severity.HIGH
    assert e.fixed_versions == ("5.19.3", "6.2.2")


def test_load_severity_very_high(tmp_path: Path) -> None:
    p = _make_xlsx(tmp_path, VERACODE_HEADERS, [
        ["org.foo:bar:1.0", "bar", "1.0", "VERACODE", "CVE-X", "", "Very High",
         "", "", "", "", "", "", "", "", "", "2.0"],
    ])
    entries = load_veracode(p)
    assert entries[0].severity == Severity.CRITICAL


def test_load_merges_multiple_cves_for_same_dep(tmp_path: Path) -> None:
    p = _make_xlsx(tmp_path, VERACODE_HEADERS, [
        ["org.foo:bar:1.0", "bar", "1.0", "VERACODE", "CVE-A", "", "High",
         "", "", "", "", "", "", "", "", "", "2.0"],
        ["org.foo:bar:1.0", "bar", "1.0", "VERACODE", "CVE-B", "", "Medium",
         "", "", "", "", "", "", "", "", "", "3.0"],
    ])
    entries = load_veracode(p)
    assert len(entries) == 1
    e = entries[0]
    assert "CVE-A" in e.cve and "CVE-B" in e.cve
    # max severity wins
    assert e.severity == Severity.HIGH
    # fixed_versions are unioned
    assert set(e.fixed_versions) == {"2.0", "3.0"}


def test_load_messy_fixed_version_string(tmp_path: Path) -> None:
    p = _make_xlsx(tmp_path, VERACODE_HEADERS, [
        ["org.foo:bar:1.0", "bar", "1.0", "VERACODE", "CVE-X", "", "High",
         "", "", "", "", "", "", "", "", "",
         "5.19.3, 5.19.3 ? Version ? 5.19.3, 6.2.2, 6.2.2 ? Version ? 6.2.2"],
    ])
    entries = load_veracode(p)
    assert entries[0].fixed_versions == ("5.19.3", "6.2.2")


def test_auto_detect_via_load_vulnerable_libs(tmp_path: Path) -> None:
    p = _make_xlsx(tmp_path, VERACODE_HEADERS, [
        ["org.foo:bar:1.0", "bar", "1.0", "VERACODE", "CVE-X", "", "High",
         "", "", "", "", "", "", "", "", "", "2.0"],
    ])
    entries = load_vulnerable_libs(p)
    assert len(entries) == 1
    assert entries[0].group_id == "org.foo"
    assert entries[0].fixed_versions == ("2.0",)
