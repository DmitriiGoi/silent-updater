from __future__ import annotations

from pathlib import Path

from silent_updater.models import RunReport


def render_report(report: RunReport) -> str:
    lines: list[str] = []
    lines.append(f"# Silent Updater Report — {report.started_at or '?'}")
    lines.append("")
    lines.append(f"- Repo: `{report.repo_url}`")
    lines.append(f"- Branch: `{report.branch or '(none)'}`")
    lines.append(f"- PR: {report.pr_url or '(not opened)'}")
    if report.finished_at:
        lines.append(f"- Finished: {report.finished_at}")
    lines.append("")
    lines.append(f"**Summary:** "
                 f"updated {len(report.succeeded)}, "
                 f"gave up on {len(report.gave_up)}, "
                 f"skipped {len(report.skipped)}.")
    lines.append("")

    if report.succeeded:
        lines.append("## ✔ Updated")
        lines.append("")
        lines.append("| GA | From | To | CVE | Severity | Strategy | Attempts |")
        lines.append("|---|---|---|---|---|---|---|")
        for o in report.succeeded:
            lines.append(
                f"| `{o.entry.ga}` | {o.entry.vuln_version} | "
                f"{o.final_version or '?'} | {o.entry.cve or '-'} | "
                f"{o.entry.severity.value} | {o.final_strategy or '-'} | "
                f"{len(o.attempts)} |"
            )
        lines.append("")

    if report.gave_up:
        lines.append("## ✗ Could not update")
        lines.append("")
        for o in report.gave_up:
            lines.append(f"### `{o.entry.ga}` ({o.entry.severity.value}, "
                         f"{o.entry.cve or 'no-cve'})")
            lines.append(f"Vulnerable version: `{o.entry.vuln_version}`")
            if o.attempts:
                lines.append("")
                lines.append("Attempts:")
                for a in o.attempts:
                    bits = [f"strategy=`{a.strategy or '-'}`",
                            f"to=`{a.to_version or '-'}`",
                            f"verdict=`{a.verdict}`"]
                    if a.note:
                        bits.append(f"note={a.note}")
                    lines.append(f"- {', '.join(bits)}")
            lines.append("")

    if report.skipped:
        lines.append("## ⊘ Skipped")
        lines.append("")
        for o in report.skipped:
            reason = ""
            if o.attempts:
                reason = o.attempts[-1].note
            lines.append(f"- `{o.entry.ga}` — {reason or 'no reason given'}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("Full tool-call transcript: see `run.log.jsonl` in workdir if enabled.")
    return "\n".join(lines)


def write_report(report: RunReport, path: Path | str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_report(report), encoding="utf-8")
    return p
