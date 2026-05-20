from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from openpyxl import Workbook

from silent_updater.tools import maven_ops, pipeline_ops
from silent_updater.tools.maven_ops import TreeAnalysis


GIT = shutil.which("git")
requires_git = pytest.mark.skipif(GIT is None, reason="git not installed")


@dataclass
class FakeMavenState:
    """Programmable backend for the maven_ops layer. Tracks calls + returns canned results."""
    tree_by_ga: dict[str | None, TreeAnalysis] = field(default_factory=dict)
    available_versions: dict[str, list[str]] = field(default_factory=dict)
    apply_calls: list[tuple] = field(default_factory=list)
    verify_by_ga: dict[str, list[dict]] = field(default_factory=dict)
    pipeline_results: list[pipeline_ops.PipelineResult] = field(default_factory=list)

    def pop_pipeline(self) -> pipeline_ops.PipelineResult:
        if len(self.pipeline_results) == 1:
            return self.pipeline_results[0]
        return self.pipeline_results.pop(0)

    def pop_verify(self, ga: str) -> dict:
        results = self.verify_by_ga.get(ga, [])
        if not results:
            return {"resolved": True, "current_version": "?", "note": "default"}
        if len(results) == 1:
            return results[0]
        return results.pop(0)


@pytest.fixture
def maven_state(monkeypatch) -> FakeMavenState:
    state = FakeMavenState()

    def fake_tree(workdir, ga=None):
        if ga in state.tree_by_ga:
            return state.tree_by_ga[ga]
        if None in state.tree_by_ga:
            return state.tree_by_ga[None]
        # Build a "full" tree from all per-ga entries when None wasn't set.
        all_paths = []
        for paths in state.tree_by_ga.values():
            all_paths.extend(paths.paths)
        return TreeAnalysis(paths=all_paths)

    def fake_full_tree(workdir):
        return fake_tree(workdir, ga=None)

    def fake_effective_version(workdir, ga):
        tree = fake_tree(workdir, ga=ga)
        versions = tree.all_versions_of(ga)
        return versions[0] if versions else None

    def fake_available(workdir, ga):
        return state.available_versions.get(ga, [])

    def fake_all_updates(workdir):
        # Aggregate latest version per GA from state.available_versions.
        return {ga: vs[0] for ga, vs in state.available_versions.items() if vs}

    def fake_probe(workdir, ga, version):
        return version in state.available_versions.get(ga, [])

    def fake_bump_direct(workdir, ga, version):
        state.apply_calls.append(("bump_direct", ga, version))

    def fake_bump_managed(workdir, ga, version):
        state.apply_calls.append(("bump_managed", ga, version))

    def fake_bump_parent(workdir, ga, version):
        state.apply_calls.append(("bump_parent", ga, version))

    def fake_dm_override(pom_path, ga, version):
        state.apply_calls.append(("dm_override", ga, version))
        # write a marker to the pom to make git see it as changed
        Path(pom_path).write_bytes(Path(pom_path).read_bytes() + b"\n<!-- dm_override -->\n")

    def fake_exclusion(pom_path, parent_ga, vuln_ga, version):
        state.apply_calls.append(("exclusion", parent_ga, vuln_ga, version))
        Path(pom_path).write_bytes(Path(pom_path).read_bytes() + b"\n<!-- excl -->\n")

    def fake_bom_import(pom_path, ga, version):
        state.apply_calls.append(("bom_import", ga, version))
        Path(pom_path).write_bytes(Path(pom_path).read_bytes() + b"\n<!-- bom -->\n")

    def fake_verify(workdir, ga, vuln_version):
        return state.pop_verify(ga)

    def fake_pipeline(command, cwd, timeout=1800, log_dir=None):
        return state.pop_pipeline()

    monkeypatch.setattr(maven_ops, "dependency_tree", fake_tree)
    monkeypatch.setattr(maven_ops, "full_dependency_tree", fake_full_tree)
    monkeypatch.setattr(maven_ops, "effective_version", fake_effective_version)
    monkeypatch.setattr(maven_ops, "list_available_versions", fake_available)
    monkeypatch.setattr(maven_ops, "all_available_updates", fake_all_updates)
    monkeypatch.setattr(maven_ops, "probe_version_exists", fake_probe)
    monkeypatch.setattr(maven_ops, "bump_direct_version", fake_bump_direct)
    monkeypatch.setattr(maven_ops, "bump_managed_version", fake_bump_managed)
    monkeypatch.setattr(maven_ops, "bump_parent_version", fake_bump_parent)
    monkeypatch.setattr(maven_ops, "add_dependency_management_override", fake_dm_override)
    monkeypatch.setattr(maven_ops, "add_exclusion_and_direct", fake_exclusion)
    monkeypatch.setattr(maven_ops, "bump_bom_import", fake_bom_import)
    monkeypatch.setattr(maven_ops, "verify_vuln_resolved", fake_verify)
    monkeypatch.setattr(pipeline_ops, "run_pipeline", fake_pipeline)
    return state


@pytest.fixture
def maven_repo(tmp_path: Path) -> Path:
    """Creates a local git repo with a minimal pom.xml. Returns the working dir."""
    if GIT is None:
        pytest.skip("git not installed")
    pom = """<?xml version='1.0' encoding='UTF-8'?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.10</version>
    </dependency>
  </dependencies>
</project>
"""
    upstream = tmp_path / "upstream.git"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(upstream)],
                   check=True, capture_output=True)
    seed = tmp_path / "seed"
    seed.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(seed)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.name", "t"], check=True)
    (seed / "pom.xml").write_text(pom, encoding="utf-8")
    subprocess.run(["git", "-C", str(seed), "add", "pom.xml"], check=True)
    subprocess.run(["git", "-C", str(seed), "commit", "-m", "init"],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "remote", "add", "origin", str(upstream)], check=True)
    subprocess.run(["git", "-C", str(seed), "push", "-u", "origin", "main"],
                   check=True, capture_output=True)

    work = tmp_path / "work"
    subprocess.run(["git", "clone", str(upstream), str(work)],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(work), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(work), "config", "user.name", "t"], check=True)
    return work


def make_vuln_xlsx(tmp_path: Path, rows: list[dict]) -> Path:
    wb = Workbook()
    ws = wb.active
    ws.append(["groupId", "artifactId", "vulnerableVersion", "cve", "severity"])
    for r in rows:
        ws.append([
            r.get("groupId", ""), r.get("artifactId", ""),
            r.get("vulnerableVersion", ""), r.get("cve", ""),
            r.get("severity", "HIGH"),
        ])
    path = tmp_path / "vulns.xlsx"
    wb.save(path)
    return path
