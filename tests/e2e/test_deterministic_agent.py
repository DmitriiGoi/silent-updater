from __future__ import annotations

from pathlib import Path

from silent_updater.agent.deterministic import DeterministicUpdaterAgent
from silent_updater.inputs.compliance import ComplianceConfig, Exception_
from silent_updater.models import Severity, VulnEntry
from silent_updater.tools import pipeline_ops
from silent_updater.tools.maven_ops import TreeAnalysis, TreeNode, TreePath

from tests.e2e.conftest import FakeMavenState, requires_git


def _ok():
    return pipeline_ops.PipelineResult(0, "BUILD SUCCESS", "", "", 1.0, False)


def _fail(stderr=""):
    return pipeline_ops.PipelineResult(1, "", stderr, "", 1.0, False)


def _make_agent(workdir: Path, vulns: list[VulnEntry],
                compliance: ComplianceConfig | None = None) -> DeterministicUpdaterAgent:
    return DeterministicUpdaterAgent(
        workdir=workdir,
        repo_url=str(workdir),
        pipeline_cmd="mvn test",
        pipeline_timeout=10,
        vuln_entries=vulns,
        compliance=compliance or ComplianceConfig(branch_template="deps/test"),
        bitbucket=None,
    )


@requires_git
def test_direct_dep_success(maven_repo: Path, maven_state: FakeMavenState) -> None:
    ga = "org.apache.commons:commons-lang3"
    maven_state.tree_by_ga[ga] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode(*ga.split(":"), type="jar", version="3.10", scope="compile", depth=1),
        )),
    ])
    maven_state.available_versions[ga] = ["3.12.0", "3.14.0", "4.0"]
    maven_state.verify_by_ga[ga] = [{"resolved": True, "current_version": "3.12.0", "note": ""}]
    maven_state.pipeline_results.append(_ok())

    # Make bump_direct actually modify pom so git sees a diff
    import silent_updater.tools.maven_ops as mops
    orig = mops.bump_direct_version

    def real_bump(workdir, ga_, version):
        (workdir / "pom.xml").write_text(
            (workdir / "pom.xml").read_text().replace("3.10", version),
            encoding="utf-8",
        )
        orig(workdir, ga_, version)

    mops.bump_direct_version = real_bump  # type: ignore
    try:
        agent = _make_agent(
            maven_repo,
            [VulnEntry(*ga.split(":"), vuln_version="3.10",
                       cve="CVE-X", severity=Severity.HIGH)],
        )
        report = agent.run()
    finally:
        mops.bump_direct_version = orig  # type: ignore

    assert len(report.succeeded) == 1
    s = report.succeeded[0]
    # Strategy "patch_minor" — should pick smallest bump first: 3.12.0
    assert s.final_version == "3.12.0"
    assert s.final_strategy == "bump_direct"
    assert ("bump_direct", ga, "3.12.0") in maven_state.apply_calls
    # 4.0 is major bump — must be filtered out by patch_minor strategy
    assert ("bump_direct", ga, "4.0") not in maven_state.apply_calls


@requires_git
def test_transitive_uses_dm_override(maven_repo: Path, maven_state: FakeMavenState) -> None:
    vuln_ga = "org.snakeyaml:snakeyaml"
    maven_state.tree_by_ga[vuln_ga] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode("org.foo", "lib-a", "jar", "1.0", "compile", 1),
            TreeNode(*vuln_ga.split(":"), type="jar", version="1.30", scope="compile", depth=2),
        )),
    ])
    maven_state.available_versions[vuln_ga] = ["1.33", "2.0"]
    maven_state.verify_by_ga[vuln_ga] = [{"resolved": True, "current_version": "1.33", "note": ""}]
    maven_state.pipeline_results.append(_ok())

    agent = _make_agent(
        maven_repo,
        [VulnEntry(*vuln_ga.split(":"), vuln_version="1.30",
                   cve="CVE-Y", severity=Severity.HIGH)],
    )
    report = agent.run()

    assert len(report.succeeded) == 1
    assert report.succeeded[0].final_strategy == "dm_override"
    assert ("dm_override", vuln_ga, "1.33") in maven_state.apply_calls


@requires_git
def test_skip_excepted(maven_repo: Path, maven_state: FakeMavenState) -> None:
    vuln_ga = "org.legacy:thing"
    compliance = ComplianceConfig(
        branch_template="deps/test",
        exceptions=[Exception_(ga=vuln_ga, reason="manual migration")],
    )
    agent = _make_agent(
        maven_repo,
        [VulnEntry(*vuln_ga.split(":"), vuln_version="1.0",
                   cve="CVE-Z", severity=Severity.HIGH)],
        compliance=compliance,
    )
    report = agent.run()
    assert len(report.succeeded) == 0
    assert len(report.skipped) == 1
    assert report.skipped[0].attempts[0].note.startswith("in exceptions")


@requires_git
def test_gave_up_when_no_acceptable_versions(maven_repo: Path,
                                             maven_state: FakeMavenState) -> None:
    vuln_ga = "org.foo:bar"
    maven_state.tree_by_ga[vuln_ga] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode("org.foo", "bar", "jar", "1.0", "compile", 1),
        )),
    ])
    # Only major bump available; patch_minor strategy should reject it.
    maven_state.available_versions[vuln_ga] = ["3.0"]

    agent = _make_agent(
        maven_repo,
        [VulnEntry(*vuln_ga.split(":"), vuln_version="1.0",
                   cve="CVE-Z", severity=Severity.HIGH)],
    )
    report = agent.run()
    assert len(report.succeeded) == 0
    assert len(report.gave_up) == 1


@requires_git
def test_retries_then_succeeds(maven_repo: Path, maven_state: FakeMavenState) -> None:
    """Smallest bump compiles but doesn't resolve the vuln; next one works."""
    vuln_ga = "org.snakeyaml:snakeyaml"
    maven_state.tree_by_ga[vuln_ga] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode("org.foo", "lib-a", "jar", "1.0", "compile", 1),
            TreeNode(*vuln_ga.split(":"), type="jar", version="1.30", scope="compile", depth=2),
        )),
    ])
    maven_state.available_versions[vuln_ga] = ["1.31", "1.33"]
    # First verify: not resolved. Second: resolved.
    maven_state.verify_by_ga[vuln_ga] = [
        {"resolved": False, "current_version": "1.30", "note": "still in tree"},
        {"resolved": True, "current_version": "1.33", "note": ""},
    ]
    maven_state.pipeline_results.extend([_ok(), _ok()])

    agent = _make_agent(
        maven_repo,
        [VulnEntry(*vuln_ga.split(":"), vuln_version="1.30",
                   cve="CVE-Y", severity=Severity.HIGH)],
    )
    report = agent.run()
    assert len(report.succeeded) == 1
    outcome = report.succeeded[0]
    assert outcome.final_version == "1.33"
    assert [a.verdict for a in outcome.attempts] == ["retry", "success"]
