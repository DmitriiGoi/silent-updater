from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from silent_updater.tools import git_ops


GIT = shutil.which("git")
requires_git = pytest.mark.skipif(GIT is None, reason="git not installed")


@requires_git
def test_full_workflow(tmp_path: Path) -> None:
    """End-to-end test against a real local git repo. No network."""
    upstream = tmp_path / "upstream.git"
    subprocess.run(
        ["git", "init", "--bare", "-b", "main", str(upstream)],
        check=True, capture_output=True,
    )

    seed = tmp_path / "seed"
    seed.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(seed)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.name", "t"], check=True)
    (seed / "file.txt").write_text("original\n")
    subprocess.run(["git", "-C", str(seed), "add", "file.txt"], check=True)
    subprocess.run(["git", "-C", str(seed), "commit", "-m", "init"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "remote", "add", "origin", str(upstream)], check=True)
    subprocess.run(["git", "-C", str(seed), "push", "-u", "origin", "main"], check=True, capture_output=True)

    work = tmp_path / "work"
    git_ops.clone(str(upstream), work)
    subprocess.run(["git", "-C", str(work), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(work), "config", "user.name", "t"], check=True)

    git_ops.create_branch("feature/x", cwd=work)
    assert git_ops.current_branch(work) == "feature/x"

    (work / "file.txt").write_text("modified\n")
    assert git_ops.has_uncommitted_changes(work) is True
    files = git_ops.list_changed_files(work)
    assert "file.txt" in files

    git_ops.add(["file.txt"], cwd=work)
    sha = git_ops.commit("test commit", cwd=work)
    assert len(sha) == 40
    assert git_ops.has_uncommitted_changes(work) is False

    # Test rollback
    (work / "file.txt").write_text("changed again\n")
    git_ops.checkout_file("file.txt", cwd=work)
    assert (work / "file.txt").read_text() == "modified\n"

    git_ops.push_branch("feature/x", cwd=work)
    # Verify pushed branch exists in upstream
    result = subprocess.run(
        ["git", "-C", str(upstream), "branch", "--list"],
        check=True, capture_output=True, text=True,
    )
    assert "feature/x" in result.stdout


@requires_git
def test_clone_failure_raises(tmp_path: Path) -> None:
    target = tmp_path / "out"
    with pytest.raises(git_ops.GitError):
        git_ops.clone("file:///nonexistent/repo.git", target)
