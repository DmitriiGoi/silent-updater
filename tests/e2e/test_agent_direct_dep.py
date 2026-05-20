from __future__ import annotations

from pathlib import Path

from silent_updater.agent.dependency_updater import DependencyUpdaterAgent
from silent_updater.inputs.compliance import ComplianceConfig
from silent_updater.models import Severity, VulnEntry
from silent_updater.tools import pipeline_ops
from silent_updater.tools.maven_ops import TreeAnalysis, TreeNode, TreePath

from tests.e2e.conftest import FakeMavenState, requires_git
from tests.e2e.fake_llm import ScriptedLLM, _stop, tool_call


def _pipeline_ok() -> pipeline_ops.PipelineResult:
    return pipeline_ops.PipelineResult(
        exit_code=0, stdout_tail="BUILD SUCCESS",
        stderr_tail="", full_log_path="", duration_seconds=1.0, timed_out=False,
    )


@requires_git
def test_direct_dep_happy_path(maven_repo: Path, maven_state: FakeMavenState) -> None:
    # Vuln dep is a DIRECT dep already in the pom (commons-lang3:3.10).
    ga = "org.apache.commons:commons-lang3"
    maven_state.tree_by_ga[None] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode("org.apache.commons", "commons-lang3", "jar", "3.10", "compile", 1),
        )),
    ])
    maven_state.tree_by_ga[ga] = maven_state.tree_by_ga[None]
    maven_state.available_versions[ga] = ["3.14.0"]
    maven_state.verify_by_ga[ga] = [{"resolved": True, "current_version": "3.14.0", "note": ""}]
    maven_state.pipeline_results.append(_pipeline_ok())

    # Force maven_ops.bump_direct_version to also touch the pom (so git sees diff).
    import silent_updater.tools.maven_ops as mops
    original_bump = mops.bump_direct_version

    def bump_and_modify(workdir, ga_, version):
        pom = workdir / "pom.xml"
        pom.write_text(pom.read_text().replace("3.10", version), encoding="utf-8")
        original_bump(workdir, ga_, version)  # records to apply_calls via monkeypatched fake

    mops.bump_direct_version = bump_and_modify  # type: ignore[assignment]
    try:
        llm = ScriptedLLM([
            tool_call("create_branch", {"name": "deps/test-branch"}),
            tool_call("bump_direct_version", {"ga": ga, "version": "3.14.0"}),
            tool_call("run_pipeline"),
            tool_call("verify_vuln_resolved", {"ga": ga, "vuln_version": "3.10"}),
            tool_call("git_commit", {
                "paths": ["pom.xml"],
                "message": "fix(deps): bump commons-lang3 3.10 -> 3.14.0",
            }),
            tool_call("record_outcome", {
                "ga": ga, "from_version": "3.10", "to_version": "3.14.0",
                "strategy": "bump_direct", "verdict": "success",
            }),
            tool_call("push_branch"),
            tool_call("write_report"),
            _stop("all done"),
        ])
        compliance = ComplianceConfig(branch_template="deps/test-branch")
        agent = DependencyUpdaterAgent(
            workdir=maven_repo,
            repo_url=str(maven_repo),
            pipeline_cmd="mvn test",
            pipeline_timeout=10,
            vuln_entries=[VulnEntry(
                group_id="org.apache.commons", artifact_id="commons-lang3",
                vuln_version="3.10", cve="CVE-X", severity=Severity.HIGH,
            )],
            compliance=compliance,
            bitbucket=None,
            llm_client=llm,
            model="fake",
        )
        report = agent.run()
    finally:
        mops.bump_direct_version = original_bump  # type: ignore[assignment]

    assert len(report.succeeded) == 1
    assert report.succeeded[0].entry.ga == ga
    assert report.branch == "deps/test-branch"
    assert (maven_repo / "update_report.md").exists()
    md = (maven_repo / "update_report.md").read_text(encoding="utf-8")
    assert "commons-lang3" in md
    assert "3.14.0" in md
