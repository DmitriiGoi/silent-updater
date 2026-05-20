from __future__ import annotations

from pathlib import Path

from silent_updater.agent.dependency_updater import DependencyUpdaterAgent
from silent_updater.inputs.compliance import ComplianceConfig
from silent_updater.models import Severity, VulnEntry
from silent_updater.tools import pipeline_ops
from silent_updater.tools.maven_ops import TreeAnalysis, TreeNode, TreePath

from tests.e2e.conftest import FakeMavenState, requires_git
from tests.e2e.fake_llm import ScriptedLLM, _stop, tool_call


def _ok():
    return pipeline_ops.PipelineResult(0, "BUILD SUCCESS", "", "", 1.0, False)


def _fail(stderr_tail: str):
    return pipeline_ops.PipelineResult(1, "", stderr_tail, "", 1.0, False)


@requires_git
def test_retry_after_pipeline_failure(maven_repo: Path,
                                      maven_state: FakeMavenState) -> None:
    """LLM tries version 4.0 → compile fails → falls back to 3.14 → succeeds."""
    ga = "org.apache.commons:commons-lang3"

    maven_state.tree_by_ga[ga] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode(*ga.split(":"), type="jar", version="3.10", scope="compile", depth=1),
        )),
    ])
    maven_state.available_versions[ga] = ["4.0", "3.14.0"]
    maven_state.verify_by_ga[ga] = [
        {"resolved": True, "current_version": "3.14.0", "note": ""},
    ]
    # First pipeline fails (compile error), second passes.
    maven_state.pipeline_results.extend([
        _fail("symbol not found: lang3.OldClass"),
        _ok(),
    ])

    # Need the bumps to actually touch pom.xml so git operations are meaningful.
    import silent_updater.tools.maven_ops as mops
    orig = mops.bump_direct_version

    versions_used: list[str] = []

    def bump_recording(workdir, ga_, version):
        versions_used.append(version)
        pom = workdir / "pom.xml"
        # Replace whatever version is there with the new one
        text = pom.read_text()
        for old in ["3.10", "4.0"]:
            text = text.replace(f"<version>{old}</version>", f"<version>{version}</version>")
        pom.write_text(text, encoding="utf-8")
        orig(workdir, ga_, version)

    mops.bump_direct_version = bump_recording  # type: ignore
    try:
        llm = ScriptedLLM([
            tool_call("create_branch", {"name": "deps/test"}),
            # Attempt 1: aggressive bump
            tool_call("bump_direct_version", {"ga": ga, "version": "4.0"}),
            tool_call("run_pipeline"),
            tool_call("git_checkout_file", {"paths": ["pom.xml"]}),
            tool_call("record_outcome", {
                "ga": ga, "from_version": "3.10", "to_version": "4.0",
                "strategy": "bump_direct", "verdict": "retry",
                "note": "compile failure: symbol not found",
            }),
            # Attempt 2: conservative bump
            tool_call("bump_direct_version", {"ga": ga, "version": "3.14.0"}),
            tool_call("run_pipeline"),
            tool_call("verify_vuln_resolved", {"ga": ga, "vuln_version": "3.10"}),
            tool_call("git_commit", {"paths": ["pom.xml"],
                                     "message": "fix(deps): bump 3.10 -> 3.14.0"}),
            tool_call("record_outcome", {
                "ga": ga, "from_version": "3.10", "to_version": "3.14.0",
                "strategy": "bump_direct", "verdict": "success",
            }),
            tool_call("write_report"),
            _stop("done"),
        ])
        agent = DependencyUpdaterAgent(
            workdir=maven_repo,
            repo_url=str(maven_repo),
            pipeline_cmd="mvn test",
            pipeline_timeout=10,
            vuln_entries=[VulnEntry(
                *ga.split(":"), vuln_version="3.10",
                cve="CVE-Z", severity=Severity.HIGH,
            )],
            compliance=ComplianceConfig(branch_template="deps/test"),
            bitbucket=None,
            llm_client=llm,
            model="fake",
        )
        report = agent.run()
    finally:
        mops.bump_direct_version = orig  # type: ignore

    assert versions_used == ["4.0", "3.14.0"]
    assert len(report.succeeded) == 1
    outcome = report.succeeded[0]
    assert outcome.final_version == "3.14.0"
    # Two attempts recorded: first retry, then success.
    assert [a.verdict for a in outcome.attempts] == ["retry", "success"]
