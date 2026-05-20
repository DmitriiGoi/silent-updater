from __future__ import annotations

from pathlib import Path

from silent_updater.agent.deterministic import DeterministicUpdaterAgent
from silent_updater.inputs.compliance import ComplianceConfig
from silent_updater.models import Severity, VulnEntry
from silent_updater.tools import pipeline_ops
from silent_updater.tools.maven_ops import TreeAnalysis, TreeNode, TreePath

from tests.e2e.conftest import FakeMavenState, requires_git


def _ok():
    return pipeline_ops.PipelineResult(0, "BUILD SUCCESS", "", "", 1.0, False)


def _fail(stderr=""):
    return pipeline_ops.PipelineResult(1, "", stderr, "", 1.0, False)


def _make_agent(workdir: Path, vulns: list[VulnEntry],
                quick_cmd: str | None) -> DeterministicUpdaterAgent:
    return DeterministicUpdaterAgent(
        workdir=workdir,
        repo_url=str(workdir),
        pipeline_cmd="mvn clean test",
        pipeline_timeout=10,
        vuln_entries=vulns,
        compliance=ComplianceConfig(branch_template="deps/test"),
        bitbucket=None,
        quick_pipeline_cmd=quick_cmd,
        quick_pipeline_timeout=5,
    )


@requires_git
def test_quick_fail_short_circuits_full(maven_repo: Path,
                                        maven_state: FakeMavenState) -> None:
    """Quick pipeline fails → full pipeline must NOT be invoked."""
    vuln_ga = "org.foo:bar"
    maven_state.tree_by_ga[vuln_ga] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode(*vuln_ga.split(":"), type="jar", version="1.0", scope="compile", depth=1),
        )),
    ])
    # ONLY a quick-fail is queued. If full pipeline gets invoked, pop_pipeline
    # will raise IndexError — which is exactly the assertion we want.
    maven_state.pipeline_results.append(_fail("compile broken"))

    agent = _make_agent(
        maven_repo,
        [VulnEntry(*vuln_ga.split(":"), vuln_version="1.0",
                   cve="CVE-X", severity=Severity.HIGH,
                   fixed_versions=("1.5",))],
        quick_cmd="mvn -q compile",
    )
    report = agent.run()

    # No success — agent retried then gave up (no more candidates).
    assert len(report.succeeded) == 0
    assert len(report.gave_up) == 1
    # Quick pipeline ate the only result; full was never called (else IndexError)
    assert len(maven_state.pipeline_results) == 0


@requires_git
def test_quick_pass_then_full(maven_repo: Path,
                              maven_state: FakeMavenState) -> None:
    """Quick passes → full pipeline runs → success."""
    vuln_ga = "org.foo:bar"
    maven_state.tree_by_ga[vuln_ga] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode(*vuln_ga.split(":"), type="jar", version="1.0", scope="compile", depth=1),
        )),
    ])
    maven_state.available_versions[vuln_ga] = ["1.5"]
    maven_state.verify_by_ga[vuln_ga] = [{"resolved": True, "current_version": "1.5", "note": ""}]
    # Order matters: quick first, full second
    maven_state.pipeline_results.extend([_ok(), _ok()])

    agent = _make_agent(
        maven_repo,
        [VulnEntry(*vuln_ga.split(":"), vuln_version="1.0",
                   cve="CVE-X", severity=Severity.HIGH,
                   fixed_versions=("1.5",))],
        quick_cmd="mvn -q compile",
    )
    report = agent.run()

    assert len(report.succeeded) == 1
    assert report.succeeded[0].final_version == "1.5"
    # Both pipelines were consumed
    assert len(maven_state.pipeline_results) == 0


@requires_git
def test_no_quick_cmd_keeps_old_behavior(maven_repo: Path,
                                        maven_state: FakeMavenState) -> None:
    """When quick_pipeline_cmd is None, only the full pipeline is invoked."""
    vuln_ga = "org.foo:bar"
    maven_state.tree_by_ga[vuln_ga] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode(*vuln_ga.split(":"), type="jar", version="1.0", scope="compile", depth=1),
        )),
    ])
    maven_state.available_versions[vuln_ga] = ["1.5"]
    maven_state.verify_by_ga[vuln_ga] = [{"resolved": True, "current_version": "1.5", "note": ""}]
    # Only one pipeline result needed because no quick stage.
    maven_state.pipeline_results.append(_ok())

    agent = _make_agent(
        maven_repo,
        [VulnEntry(*vuln_ga.split(":"), vuln_version="1.0",
                   cve="CVE-X", severity=Severity.HIGH,
                   fixed_versions=("1.5",))],
        quick_cmd=None,
    )
    report = agent.run()
    assert len(report.succeeded) == 1
