from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


class GitError(RuntimeError):
    def __init__(self, cmd: list[str], returncode: int, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"git {' '.join(cmd)} -> exit {returncode}\n{stderr}")


@dataclass(frozen=True)
class GitResult:
    stdout: str
    stderr: str
    returncode: int


def _run(args: list[str], cwd: Path | str | None = None, timeout: int = 300) -> GitResult:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise GitError(args, proc.returncode, proc.stderr.strip())
    return GitResult(stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode)


def clone(repo_url: str, target_dir: Path | str, depth: int | None = None,
          branch: str | None = None, shallow: bool = True) -> Path:
    """Clone repo. Fast-path:
      - file:// URLs (and bare local paths) are passed as raw paths so git can
        use its hardlink-based --local optimization (instant for big repos).
      - For network URLs (http/https/ssh/git), shallow=True adds
        --depth 1 --no-tags --single-branch for a much faster clone.
    """
    args = ["clone"]
    source = repo_url
    is_local = False
    if repo_url.startswith("file://"):
        source = repo_url[len("file://"):]
        is_local = True
    elif "://" not in repo_url and not repo_url.startswith("git@"):
        # raw filesystem path
        is_local = True

    if is_local:
        args.append("--local")
    elif shallow and depth is None:
        args += ["--depth", "1", "--no-tags", "--single-branch"]
    elif depth is not None:
        args += ["--depth", str(depth)]
    if branch:
        args += ["--branch", branch]
    args += [source, str(target_dir)]
    _run(args)
    return Path(target_dir)


def current_branch(cwd: Path | str) -> str:
    return _run(["rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd).stdout.strip()


def create_branch(name: str, cwd: Path | str, base: str | None = None) -> None:
    args = ["checkout", "-b", name]
    if base:
        args.append(base)
    _run(args, cwd=cwd)


def status_porcelain(cwd: Path | str) -> str:
    return _run(["status", "--porcelain"], cwd=cwd).stdout


def add(paths: list[str], cwd: Path | str) -> None:
    if not paths:
        return
    _run(["add", "--", *paths], cwd=cwd)


def commit(message: str, cwd: Path | str) -> str:
    _run(["commit", "-m", message], cwd=cwd)
    return _run(["rev-parse", "HEAD"], cwd=cwd).stdout.strip()


def checkout_file(path: str, cwd: Path | str) -> None:
    """Rollback a single file to HEAD. Safer than `git checkout` без '--'."""
    _run(["checkout", "HEAD", "--", path], cwd=cwd)


def checkout_files(paths: list[str], cwd: Path | str) -> None:
    if not paths:
        return
    _run(["checkout", "HEAD", "--", *paths], cwd=cwd)


def push_branch(branch: str, cwd: Path | str, remote: str = "origin",
                set_upstream: bool = True) -> None:
    args = ["push"]
    if set_upstream:
        args.append("-u")
    args += [remote, branch]
    _run(args, cwd=cwd)


def has_uncommitted_changes(cwd: Path | str) -> bool:
    return bool(status_porcelain(cwd).strip())


def head_sha(cwd: Path | str) -> str:
    return _run(["rev-parse", "HEAD"], cwd=cwd).stdout.strip()


def list_changed_files(cwd: Path | str) -> list[str]:
    out = status_porcelain(cwd)
    files: list[str] = []
    for line in out.splitlines():
        if len(line) < 3:
            continue
        files.append(line[3:].strip())
    return files
