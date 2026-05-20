from __future__ import annotations

from pathlib import Path

from silent_updater.models import (
    AttemptLog,
    DepOutcome,
    RunReport,
    Severity,
    VulnEntry,
)
from silent_updater.reporter import render_report, write_report


def _vuln(ga: str = "org.foo:bar", severity: Severity = Severity.HIGH) -> VulnEntry:
    g, a = ga.split(":")
    return VulnEntry(group_id=g, artifact_id=a, vuln_version="1.0",
                     cve="CVE-X", severity=severity)


def test_render_includes_succeeded_table() -> None:
    report = RunReport(repo_url="r", branch="b", started_at="2026-05-20")
    out = DepOutcome(entry=_vuln("a:b"))
    out.final_verdict = "success"
    out.final_version = "2.0"
    out.final_strategy = "bump_direct"
    out.attempts.append(AttemptLog(
        ga="a:b", from_version="1.0", to_version="2.0",
        strategy="bump_direct", pipeline_exit=0,
        stderr_excerpt="", verdict="success",
    ))
    report.outcomes.append(out)
    md = render_report(report)
    assert "## ✔ Updated" in md
    assert "`a:b`" in md
    assert "2.0" in md
    assert "bump_direct" in md


def test_render_gave_up_section() -> None:
    report = RunReport(repo_url="r", branch="b", started_at="t")
    out = DepOutcome(entry=_vuln("x:y"))
    out.final_verdict = "gave_up"
    out.attempts.append(AttemptLog(
        ga="x:y", from_version="1", to_version="2", strategy="dm_override",
        pipeline_exit=1, stderr_excerpt="...", verdict="retry",
        note="compile failure",
    ))
    report.outcomes.append(out)
    md = render_report(report)
    assert "## ✗ Could not update" in md
    assert "compile failure" in md


def test_write_report_creates_file(tmp_path: Path) -> None:
    report = RunReport(repo_url="r", branch="b", started_at="t")
    path = tmp_path / "report.md"
    write_report(report, path)
    assert path.exists()
    assert "Silent Updater Report" in path.read_text(encoding="utf-8")
