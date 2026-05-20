from __future__ import annotations

import datetime as dt
import subprocess
from dataclasses import dataclass
from pathlib import Path


TAIL_LINES = 200


@dataclass(frozen=True)
class PipelineResult:
    exit_code: int
    stdout_tail: str
    stderr_tail: str
    full_log_path: str
    duration_seconds: float
    timed_out: bool


def run_pipeline(
    command: str,
    cwd: Path | str,
    timeout: int = 1800,
    log_dir: Path | str | None = None,
) -> PipelineResult:
    """Run regression pipeline command in workdir. Returns tail + full log path."""
    cwd = Path(cwd)
    log_dir = Path(log_dir) if log_dir else cwd / ".silent-updater"
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = log_dir / f"pipeline-{ts}.log"

    start = dt.datetime.now()
    timed_out = False
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        exit_code = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as ex:
        timed_out = True
        exit_code = -1
        stdout = ex.stdout.decode("utf-8", errors="replace") if ex.stdout else ""
        stderr = ex.stderr.decode("utf-8", errors="replace") if ex.stderr else ""
        stderr += f"\n[silent-updater] TIMEOUT after {timeout}s\n"

    duration = (dt.datetime.now() - start).total_seconds()

    log_content = (
        f"# command: {command}\n"
        f"# cwd: {cwd}\n"
        f"# exit_code: {exit_code}\n"
        f"# duration_seconds: {duration:.1f}\n"
        f"# timed_out: {timed_out}\n"
        f"\n=== STDOUT ===\n{stdout}\n\n=== STDERR ===\n{stderr}\n"
    )
    log_path.write_text(log_content, encoding="utf-8")

    return PipelineResult(
        exit_code=exit_code,
        stdout_tail=_tail(stdout, TAIL_LINES),
        stderr_tail=_tail(stderr, TAIL_LINES),
        full_log_path=str(log_path),
        duration_seconds=duration,
        timed_out=timed_out,
    )


def _tail(text: str, n: int) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    if len(lines) <= n:
        return text
    return "\n".join(lines[-n:])
