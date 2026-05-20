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


@requires_git
def test_dm_override_after_failed_direct_bump(maven_repo: Path,
                                              maven_state: FakeMavenState) -> None:
    """vuln comes via 2 different direct deps. Bumping one isn't enough — switch
    to add_dependency_management_override which resolves the issue globally."""
    vuln_ga = "org.snakeyaml:snakeyaml"

    # Tree shows two paths to snakeyaml — from two distinct direct deps.
    maven_state.tree_by_ga[vuln_ga] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode("org.foo", "lib-a", "jar", "1.0", "compile", 1),
            TreeNode(*vuln_ga.split(":"), type="jar", version="1.30", scope="compile", depth=2),
        )),
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode("org.bar", "lib-b", "jar", "1.0", "compile", 1),
            TreeNode(*vuln_ga.split(":"), type="jar", version="1.30", scope="compile", depth=2),
        )),
    ])
    maven_state.available_versions[vuln_ga] = ["2.2"]

    # First verify (after direct bump on lib-a): not resolved — lib-b still pulls 1.30.
    # Second verify (after dm_override): resolved.
    maven_state.verify_by_ga[vuln_ga] = [
        {"resolved": False, "current_version": "1.30", "note": "lib-b still pulls"},
        {"resolved": True, "current_version": "2.2", "note": ""},
    ]
    # Pipeline passes both times (build is fine, just the version pin doesn't work yet).
    maven_state.pipeline_results.extend([_ok(), _ok()])

    llm = ScriptedLLM([
        tool_call("create_branch", {"name": "deps/test"}),
        tool_call("dependency_tree", {"ga": vuln_ga}),
        # First attempt: bump direct dep lib-a (won't displace lib-b's transitive)
        tool_call("bump_direct_version", {"ga": "org.foo:lib-a", "version": "1.5"}),
        tool_call("run_pipeline"),
        tool_call("verify_vuln_resolved", {"ga": vuln_ga, "vuln_version": "1.30"}),
        # Rollback — verify said not resolved
        tool_call("git_checkout_file", {"paths": ["pom.xml"]}),
        tool_call("record_outcome", {
            "ga": vuln_ga, "from_version": "1.30", "to_version": "1.30",
            "strategy": "bump_direct", "verdict": "retry",
            "note": "lib-b still pulls vulnerable version",
        }),
        # Strategy switch: dm_override
        tool_call("add_dependency_management_override",
                  {"ga": vuln_ga, "version": "2.2"}),
        tool_call("run_pipeline"),
        tool_call("verify_vuln_resolved", {"ga": vuln_ga, "vuln_version": "1.30"}),
        tool_call("git_commit", {"paths": ["pom.xml"],
                                 "message": "fix(deps): pin snakeyaml to 2.2"}),
        tool_call("record_outcome", {
            "ga": vuln_ga, "from_version": "1.30", "to_version": "2.2",
            "strategy": "dm_override", "verdict": "success",
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
            *vuln_ga.split(":"), vuln_version="1.30", cve="CVE-Y", severity=Severity.HIGH,
        )],
        compliance=ComplianceConfig(branch_template="deps/test"),
        bitbucket=None,
        llm_client=llm,
        model="fake",
    )
    report = agent.run()

    assert len(report.succeeded) == 1
    final = report.succeeded[0]
    assert final.final_strategy == "dm_override"
    assert final.final_version == "2.2"
    # Both attempts recorded
    assert len(final.attempts) == 2
    assert final.attempts[0].verdict == "retry"
    assert final.attempts[1].verdict == "success"
    # Both strategies were applied at the Maven layer
    assert ("bump_direct", "org.foo:lib-a", "1.5") in maven_state.apply_calls
    assert ("dm_override", vuln_ga, "2.2") in maven_state.apply_calls
