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


@requires_git
def test_fixed_versions_tried_before_available(maven_repo: Path,
                                               maven_state: FakeMavenState) -> None:
    """If Veracode supplied Fixed Version, agent should try those first.

    Setup: vuln 1.0 of org.foo:bar (transitive). Fixed Version says 1.5.
    `mvn versions:display-dependency-updates` would have offered 1.10 first.
    With Veracode hint, 1.5 must be tried first.
    """
    vuln_ga = "org.foo:bar"
    maven_state.tree_by_ga[vuln_ga] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode("org.parent", "lib", "jar", "1.0", "compile", 1),
            TreeNode(*vuln_ga.split(":"), type="jar", version="1.0", scope="compile", depth=2),
        )),
    ])
    # Available reports 1.10 (which would be tried first WITHOUT the hint).
    maven_state.available_versions[vuln_ga] = ["1.10"]
    maven_state.verify_by_ga[vuln_ga] = [{"resolved": True, "current_version": "1.5", "note": ""}]
    maven_state.pipeline_results.append(_ok())

    agent = DeterministicUpdaterAgent(
        workdir=maven_repo,
        repo_url=str(maven_repo),
        pipeline_cmd="mvn test",
        pipeline_timeout=10,
        vuln_entries=[VulnEntry(
            *vuln_ga.split(":"), vuln_version="1.0",
            cve="CVE-X", severity=Severity.HIGH,
            fixed_versions=("1.5",),
        )],
        compliance=ComplianceConfig(branch_template="deps/test"),
        bitbucket=None,
    )
    report = agent.run()

    assert len(report.succeeded) == 1
    s = report.succeeded[0]
    assert s.final_version == "1.5"   # used hint, not 1.10
    # Only one attempt was needed
    assert len(s.attempts) == 1


@requires_git
def test_fixed_version_falls_back_to_available_if_filtered_out(
    maven_repo: Path, maven_state: FakeMavenState,
) -> None:
    """Veracode Fixed Version is a major bump that's blocked by update_strategy.
    Falls back to available_versions for a smaller bump.
    """
    vuln_ga = "org.foo:bar"
    maven_state.tree_by_ga[vuln_ga] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode("org.parent", "lib", "jar", "1.0", "compile", 1),
            TreeNode(*vuln_ga.split(":"), type="jar", version="1.0", scope="compile", depth=2),
        )),
    ])
    # Available: small bump 1.5 (acceptable under patch_minor)
    maven_state.available_versions[vuln_ga] = ["1.5"]
    maven_state.verify_by_ga[vuln_ga] = [{"resolved": True, "current_version": "1.5", "note": ""}]
    maven_state.pipeline_results.append(_ok())

    agent = DeterministicUpdaterAgent(
        workdir=maven_repo,
        repo_url=str(maven_repo),
        pipeline_cmd="mvn test",
        pipeline_timeout=10,
        vuln_entries=[VulnEntry(
            *vuln_ga.split(":"), vuln_version="1.0",
            cve="CVE-X", severity=Severity.HIGH,
            # Fixed only in 3.0 (major bump) — blocked by patch_minor strategy
            fixed_versions=("3.0",),
        )],
        compliance=ComplianceConfig(branch_template="deps/test",
                                     update_strategy="patch_minor"),
        bitbucket=None,
    )
    report = agent.run()
    # 3.0 was filtered out; agent fell back to 1.5
    assert len(report.succeeded) == 1
    assert report.succeeded[0].final_version == "1.5"
