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


def _run(args: list[str], cwd: Path | str | None = None, timeout: int = 300,
         stream_stderr: bool = False) -> GitResult:
    """Run git. If stream_stderr=True, git's stderr goes straight to the
    terminal (used for `clone --progress` so the user sees live progress
    instead of waiting silently for several minutes).
    """
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=None if stream_stderr else subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    stderr = "" if stream_stderr else (proc.stderr or "")
    if proc.returncode != 0:
        raise GitError(args, proc.returncode, stderr.strip())
    return GitResult(stdout=proc.stdout or "", stderr=stderr, returncode=proc.returncode)


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
    # Stream stderr so the user sees live progress instead of waiting silently.
    _run(args, stream_stderr=True)
    return Path(target_dir)


def current_branch(cwd: Path | str) -> str:
    return _run(["rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd).stdout.strip()


def create_branch(name: str, cwd: Path | str, base: str | None = None) -> None:
    args = ["checkout", "-b", name]
    if base:
        args.append(base)
    _run(args, cwd=cwd)


def _branch_exists(name: str, cwd: Path | str) -> bool:
    proc = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{name}"],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def create_or_switch_branch(name: str, cwd: Path | str, base: str | None = None) -> bool:
    """Idempotent branch setup for repeated runs in the same workdir.

    - If the branch already exists: discard uncommitted changes (safe — we'd
      have rolled them back anyway on a clean re-run), check it out, return False.
    - Otherwise: create a new branch from base/HEAD, return True.
    """
    # Drop any uncommitted leftovers from a previous interrupted run.
    proc = subprocess.run(
        ["git", "stash", "push", "-u", "-m", "silent-updater pre-rerun stash"],
        cwd=str(cwd) if cwd else None,
        capture_output=True, text=True,
    )
    # ignore stash failure — it's just cleanup
    if _branch_exists(name, cwd):
        _run(["checkout", name], cwd=cwd)
        # Roll back any tracked modifications introduced by previous interrupted attempts.
        _run(["reset", "--hard", "HEAD"], cwd=cwd)
        return False
    create_branch(name, cwd, base=base)
    return True


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
