from __future__ import annotations

from pathlib import Path

from silent_updater.agent.dependency_updater import DependencyUpdaterAgent
from silent_updater.inputs.compliance import ComplianceConfig
from silent_updater.models import Severity, VulnEntry
from silent_updater.tools import pipeline_ops
from silent_updater.tools.maven_ops import TreeAnalysis, TreeNode, TreePath

from tests.e2e.conftest import FakeMavenState, requires_git
from tests.e2e.fake_llm import ScriptedLLM, _stop, tool_call


@requires_git
def test_transitive_via_bom_import(maven_repo: Path, maven_state: FakeMavenState) -> None:
    """jackson-databind is brought in transitively by a BOM. Strategy: bump_bom_import."""
    vuln_ga = "com.fasterxml.jackson.core:jackson-databind"
    bom_ga = "org.springframework.boot:spring-boot-dependencies"

    # Pom must have a BOM import so bump_bom_import actually finds it.
    pom_path = maven_repo / "pom.xml"
    pom_path.write_text("""<?xml version='1.0' encoding='UTF-8'?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>2.6.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
""", encoding="utf-8")
    import subprocess
    subprocess.run(["git", "-C", str(maven_repo), "add", "pom.xml"], check=True)
    subprocess.run(["git", "-C", str(maven_repo), "commit", "-m", "bom"],
                   check=True, capture_output=True)

    # Tree: vuln comes in via parent BOM (one path, depth=1 is BOM-imported dep)
    maven_state.tree_by_ga[vuln_ga] = TreeAnalysis(paths=[
        TreePath(nodes=(
            TreeNode("com.example", "app", "jar", "1.0.0", "", 0),
            TreeNode("org.springframework.boot", "spring-boot-starter", "jar", "2.6.0", "compile", 1),
            TreeNode(*vuln_ga.split(":"), type="jar", version="2.13.0", scope="compile", depth=2),
        )),
    ])
    maven_state.available_versions[vuln_ga] = ["2.13.5"]
    maven_state.verify_by_ga[vuln_ga] = [
        {"resolved": True, "current_version": "2.17.1", "note": "via new BOM"},
    ]
    maven_state.pipeline_results.append(pipeline_ops.PipelineResult(
        0, "BUILD SUCCESS", "", "", 1.0, False,
    ))

    llm = ScriptedLLM([
        tool_call("create_branch", {"name": "deps/test"}),
        tool_call("dependency_tree", {"ga": vuln_ga}),
        tool_call("bump_bom_import", {"bom_ga": bom_ga, "version": "2.7.18"}),
        tool_call("run_pipeline"),
        tool_call("verify_vuln_resolved", {"ga": vuln_ga, "vuln_version": "2.13.0"}),
        tool_call("git_commit", {"paths": ["pom.xml"],
                                 "message": "fix(deps): bump BOM 2.6.0 -> 2.7.18"}),
        tool_call("record_outcome", {
            "ga": vuln_ga, "from_version": "2.13.0", "to_version": "2.17.1",
            "strategy": "bump_bom_import", "verdict": "success",
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
            *vuln_ga.split(":"), vuln_version="2.13.0", cve="CVE-J", severity=Severity.CRITICAL,
        )],
        compliance=ComplianceConfig(branch_template="deps/test"),
        bitbucket=None,
        llm_client=llm,
        model="fake",
    )
    report = agent.run()

    assert len(report.succeeded) == 1
    assert report.succeeded[0].final_strategy == "bump_bom_import"
    assert ("bom_import", bom_ga, "2.7.18") in maven_state.apply_calls
